package service_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/melissa992/Taller_Criptografia_Go/internal/crypto"
	"github.com/melissa992/Taller_Criptografia_Go/internal/domain"
	"github.com/melissa992/Taller_Criptografia_Go/internal/generator"
	"github.com/melissa992/Taller_Criptografia_Go/internal/logstore"
	"github.com/melissa992/Taller_Criptografia_Go/internal/service"
)

// Fake implementations for unit testing
type fakeHasher struct {
	lastHashed []byte
}

func (f *fakeHasher) HashHex(data []byte) string {
	f.lastHashed = make([]byte, len(data))
	copy(f.lastHashed, data)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

type fakeEncryptor struct {
	failKeyGen  bool
	failEncrypt bool
	lastPlain   []byte
}

func (f *fakeEncryptor) GenerateKey() ([]byte, error) {
	if f.failKeyGen {
		return nil, errors.New("simulated keygen failure")
	}
	return bytes.Repeat([]byte{0x42}, 32), nil
}

func (f *fakeEncryptor) Encrypt(key, plaintext []byte) ([]byte, error) {
	if f.failEncrypt {
		return nil, errors.New("simulated encrypt failure")
	}
	f.lastPlain = make([]byte, len(plaintext))
	copy(f.lastPlain, plaintext)
	// Return dummy ciphertext with 12 bytes nonce prefix + data + 16 bytes tag
	nonce := bytes.Repeat([]byte{0x01}, 12)
	tag := bytes.Repeat([]byte{0x02}, 16)
	return append(append(nonce, plaintext...), tag...), nil
}

func (f *fakeEncryptor) Decrypt(key, data []byte) ([]byte, error) {
	if len(data) < 28 {
		return nil, errors.New("too short")
	}
	return data[12 : len(data)-16], nil
}

type fakeStore struct {
	files    map[string][]byte
	perms    map[string]os.FileMode
	failFile string
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		files: make(map[string][]byte),
		perms: make(map[string]os.FileMode),
	}
}

func (f *fakeStore) Save(name string, data []byte, perm os.FileMode) error {
	if f.failFile == name {
		return errors.New("simulated write error on " + name)
	}
	buf := make([]byte, len(data))
	copy(buf, data)
	f.files[name] = buf
	f.perms[name] = perm
	return nil
}

func (f *fakeStore) Load(name string) ([]byte, error) {
	data, ok := f.files[name]
	if !ok {
		return nil, os.ErrNotExist
	}
	return data, nil
}

func sampleEvents() []domain.Event {
	g := 4.0
	prev := 3.0
	newG := 4.5
	return []domain.Event{
		{
			EventID:     "evt-1",
			EventType:   domain.GradeRegistered,
			Timestamp:   "2026-11-07T12:00:00Z",
			ActorUID:    "doc-1",
			StudentUID:  "est-1",
			CourseUID:   "cur-1",
			Grade:       &g,
			PayloadHash: "hash1",
		},
		{
			EventID:       "evt-2",
			EventType:     domain.GradeModified,
			Timestamp:     "2026-11-07T12:01:00Z",
			ActorUID:      "doc-1",
			StudentUID:    "est-2",
			CourseUID:     "cur-1",
			PreviousGrade: &prev,
			NewGrade:      &newG,
			PayloadHash:   "hash2",
		},
	}
}

func TestProtectionService_EmptyEvents(t *testing.T) {
	hasher := &fakeHasher{}
	enc := &fakeEncryptor{}
	store := newFakeStore()

	svc := service.NewProtectionService(hasher, enc, store, service.WithIDFunc(func() (string, error) {
		return "test-id", nil
	}))

	_, err := svc.Protect(nil)
	if !errors.Is(err, service.ErrNoEvents) {
		t.Fatalf("expected ErrNoEvents for nil slice, got %v", err)
	}

	_, err = svc.Protect([]domain.Event{})
	if !errors.Is(err, service.ErrNoEvents) {
		t.Fatalf("expected ErrNoEvents for empty slice, got %v", err)
	}
}

func TestProtectionService_MissingIDGenerator(t *testing.T) {
	hasher := &fakeHasher{}
	enc := &fakeEncryptor{}
	store := newFakeStore()

	svc := service.NewProtectionService(hasher, enc, store) // No WithIDFunc provided

	_, err := svc.Protect(sampleEvents())
	if !errors.Is(err, service.ErrMissingIDGenerator) {
		t.Fatalf("expected ErrMissingIDGenerator, got %v", err)
	}
}

func TestProtectionService_Unit_AllArtifactsAndExactBytes(t *testing.T) {
	hasher := &fakeHasher{}
	enc := &fakeEncryptor{}
	store := newFakeStore()

	fixedTime := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return fixedTime }
	idGen := func() (string, error) { return "log-12345", nil }

	svc := service.NewProtectionService(
		hasher,
		enc,
		store,
		service.WithClock(clock),
		service.WithIDFunc(idGen),
	)

	events := sampleEvents()
	res, err := svc.Protect(events)
	if err != nil {
		t.Fatalf("Protect failed: %v", err)
	}

	// Verify ProtectionResult fields
	if res.LogID != "log-12345" {
		t.Errorf("expected LogID log-12345, got %s", res.LogID)
	}
	if res.EventCount != 2 {
		t.Errorf("expected EventCount 2, got %d", res.EventCount)
	}
	if res.EventsByType[domain.GradeRegistered] != 1 || res.EventsByType[domain.GradeModified] != 1 {
		t.Errorf("unexpected EventsByType map: %+v", res.EventsByType)
	}

	// Verify all 5 expected files exist in store
	expectedFiles := []string{
		logstore.LogFile,
		logstore.LogHashFile,
		logstore.KeyFile,
		logstore.EncryptedLogFile,
		logstore.EncryptedHashFile,
	}

	for _, fname := range expectedFiles {
		data, ok := store.files[fname]
		if !ok || len(data) == 0 {
			t.Errorf("expected artifact file %s to be saved and non-empty", fname)
		}
	}

	// Verify permissions
	if store.perms[logstore.KeyFile] != 0o600 {
		t.Errorf("expected key.bin to have permissions 0600, got %o", store.perms[logstore.KeyFile])
	}
	if store.perms[logstore.LogFile] != 0o644 {
		t.Errorf("expected log.json to have permissions 0644, got %o", store.perms[logstore.LogFile])
	}

	// Verify exact bytes requirement:
	// The bytes passed to hasher in Step 5 must be exactly the bytes stored in log.json
	logJSONBytes := store.files[logstore.LogFile]
	if !bytes.Equal(hasher.lastHashed, store.files[logstore.EncryptedLogFile]) {
		// hasher was called twice: once for log.json, once for log.enc.
		// The second call was on log.enc:
		if !bytes.Equal(hasher.lastHashed, store.files[logstore.EncryptedLogFile]) {
			t.Errorf("step 7: hash was not calculated on exact log.enc bytes")
		}
	}

	// Verify plaintext passed to encryptor in Step 6 is exactly log.json bytes
	if !bytes.Equal(enc.lastPlain, logJSONBytes) {
		t.Errorf("step 6: plaintext passed to encryptor does not match log.json bytes")
	}

	// Verify hash files have trailing newline
	if !strings.HasSuffix(string(store.files[logstore.LogHashFile]), "\n") {
		t.Errorf("log.sha256 missing trailing newline")
	}
	if !strings.HasSuffix(string(store.files[logstore.EncryptedHashFile]), "\n") {
		t.Errorf("log.enc.sha256 missing trailing newline")
	}
}

func TestProtectionService_StepFailurePropagation(t *testing.T) {
	events := sampleEvents()

	t.Run("step 4 save failure", func(t *testing.T) {
		store := newFakeStore()
		store.failFile = logstore.LogFile
		svc := service.NewProtectionService(
			&fakeHasher{},
			&fakeEncryptor{},
			store,
			service.WithIDFunc(func() (string, error) { return "id", nil }),
		)

		_, err := svc.Protect(events)
		if err == nil || !strings.Contains(err.Error(), "paso 4") {
			t.Fatalf("expected error mentioning 'paso 4', got %v", err)
		}
	})

	t.Run("step 6 keygen failure", func(t *testing.T) {
		enc := &fakeEncryptor{failKeyGen: true}
		svc := service.NewProtectionService(
			&fakeHasher{},
			enc,
			newFakeStore(),
			service.WithIDFunc(func() (string, error) { return "id", nil }),
		)

		_, err := svc.Protect(events)
		if err == nil || !strings.Contains(err.Error(), "paso 6") {
			t.Fatalf("expected error mentioning 'paso 6', got %v", err)
		}
	})

	t.Run("step 6 encrypt failure", func(t *testing.T) {
		enc := &fakeEncryptor{failEncrypt: true}
		svc := service.NewProtectionService(
			&fakeHasher{},
			enc,
			newFakeStore(),
			service.WithIDFunc(func() (string, error) { return "id", nil }),
		)

		_, err := svc.Protect(events)
		if err == nil || !strings.Contains(err.Error(), "paso 6") {
			t.Fatalf("expected error mentioning 'paso 6', got %v", err)
		}
	})
}

func TestProtectionService_Integration_RealImplementations(t *testing.T) {
	tempDir := t.TempDir()
	store := logstore.NewFileStore(tempDir)
	hasher := crypto.NewSHA256Hasher()
	encryptor := crypto.NewAESGCMEncryptor()

	svc := service.NewProtectionService(
		hasher,
		encryptor,
		store,
		service.WithIDFunc(generator.NewUUIDv4),
	)

	// Generate 20 realistic events
	eventGen := generator.NewRandomEventGenerator()
	events, err := eventGen.Generate(20)
	if err != nil {
		t.Fatalf("failed to generate events: %v", err)
	}

	result, err := svc.Protect(events)
	if err != nil {
		t.Fatalf("Protect failed: %v", err)
	}

	if result.EventCount != 20 {
		t.Fatalf("expected EventCount 20, got %d", result.EventCount)
	}

	// 1. Verify log.json and independent SHA-256 calculation
	rawPlainLog, err := store.Load(logstore.LogFile)
	if err != nil {
		t.Fatalf("failed to load log.json: %v", err)
	}

	independentPlainDigest := sha256.Sum256(rawPlainLog)
	independentPlainHex := hex.EncodeToString(independentPlainDigest[:])
	if result.PlainLogHash != independentPlainHex {
		t.Fatalf("plain hash mismatch: result=%s, independent=%s", result.PlainLogHash, independentPlainHex)
	}

	savedPlainHashBytes, err := store.Load(logstore.LogHashFile)
	if err != nil {
		t.Fatalf("failed to load log.sha256: %v", err)
	}
	if strings.TrimSpace(string(savedPlainHashBytes)) != independentPlainHex {
		t.Fatalf("saved log.sha256 does not match independent hash")
	}

	// 2. Verify log.enc and independent SHA-256 calculation
	rawEncLog, err := store.Load(logstore.EncryptedLogFile)
	if err != nil {
		t.Fatalf("failed to load log.enc: %v", err)
	}

	independentEncDigest := sha256.Sum256(rawEncLog)
	independentEncHex := hex.EncodeToString(independentEncDigest[:])
	if result.EncryptedLogHash != independentEncHex {
		t.Fatalf("encrypted hash mismatch: result=%s, independent=%s", result.EncryptedLogHash, independentEncHex)
	}

	savedEncHashBytes, err := store.Load(logstore.EncryptedHashFile)
	if err != nil {
		t.Fatalf("failed to load log.enc.sha256: %v", err)
	}
	if strings.TrimSpace(string(savedEncHashBytes)) != independentEncHex {
		t.Fatalf("saved log.enc.sha256 does not match independent encrypted hash")
	}

	// 3. Decrypt with saved key.bin and compare with log.json
	key, err := store.Load(logstore.KeyFile)
	if err != nil {
		t.Fatalf("failed to load key.bin: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(key))
	}

	decryptedBytes, err := encryptor.Decrypt(key, rawEncLog)
	if err != nil {
		t.Fatalf("failed to decrypt log.enc with key.bin: %v", err)
	}

	if !bytes.Equal(decryptedBytes, rawPlainLog) {
		t.Fatal("decrypted bytes do not match original log.json bytes exactly")
	}

	// 4. Verify unmarshaled domain.Log
	var recoveredLog domain.Log
	if err := json.Unmarshal(decryptedBytes, &recoveredLog); err != nil {
		t.Fatalf("failed to unmarshal recovered log JSON: %v", err)
	}

	if recoveredLog.EventCount != 20 || len(recoveredLog.Events) != 20 {
		t.Fatalf("recovered log event count mismatch: expected 20, got %d", recoveredLog.EventCount)
	}
}
