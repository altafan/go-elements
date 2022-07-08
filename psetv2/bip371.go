package psetv2

import (
	"bytes"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

type TaprootBip32Derivation = psbt.TaprootBip32Derivation
type TaprootScriptSpendSig = psbt.TaprootScriptSpendSig
type TaprootTapLeafScript = psbt.TaprootTapLeafScript

// validateXOnlyPubkey checks if pubKey is *any* valid pubKey serialization in a
// BIP-340 context (x-only serialization).
func validateXOnlyPubkey(pubKey []byte) bool {
	_, err := schnorr.ParsePubKey(pubKey)
	return err == nil
}

// validateSchnorrSignature checks that the passed byte slice is a valid Schnorr
// signature, _NOT_ including the sighash flag. It does *not* of course
// validate the signature against any message or public key.
func validateSchnorrSignature(sig []byte) bool {
	_, err := schnorr.ParseSignature(sig)
	return err == nil
}

// validateControlBlock checks that the passed byte slice is a valid control
// block as it would appear in a BIP-341 witness stack as the last element.
func validateControlBlock(controlBlock []byte) bool {
	_, err := txscript.ParseControlBlock(controlBlock)
	return err == nil
}

// serializeTaprootBip32Derivation serializes a TaprootBip32Derivation to its
// raw byte representation.
func serializeTaprootBip32Derivation(d *TaprootBip32Derivation) ([]byte,
	error) {

	var buf bytes.Buffer

	// The taproot key BIP 32 derivation path is defined as:
	//   <hashes len> <leaf hash>* <4 byte fingerprint> <32-bit uint>*
	err := wire.WriteVarInt(&buf, 0, uint64(len(d.LeafHashes)))
	if err != nil {
		return nil, ErrInvalidPsbtFormat
	}

	for _, hash := range d.LeafHashes {
		n, err := buf.Write(hash)
		if err != nil || n != 32 {
			return nil, ErrInvalidPsbtFormat
		}
	}

	_, err = buf.Write(SerializeBIP32Derivation(
		d.MasterKeyFingerprint, d.Bip32Path,
	))
	if err != nil {
		return nil, ErrInvalidPsbtFormat
	}

	return buf.Bytes(), nil
}

// readTaprootBip32Derivation deserializes a byte slice containing the Taproot
// BIP32 derivation info that consists of a list of leaf hashes as well as the
// normal BIP32 derivation info.
func readTaprootBip32Derivation(xOnlyPubKey,
	value []byte) (*TaprootBip32Derivation, error) {

	// The taproot key BIP 32 derivation path is defined as:
	//   <hashes len> <leaf hash>* <4 byte fingerprint> <32-bit uint>*
	// So we get at least 5 bytes for the length and the 4 byte fingerprint.
	if len(value) < 5 {
		return nil, ErrInvalidPsbtFormat
	}

	// The first element is the number of hashes that will follow.
	reader := bytes.NewReader(value)
	numHashes, err := wire.ReadVarInt(reader, 0)
	if err != nil {
		return nil, ErrInvalidPsbtFormat
	}

	// A hash is 32 bytes in size, so we need at least numHashes*32 + 5
	// bytes to be present.
	if len(value) < (int(numHashes)*32)+5 {
		return nil, ErrInvalidPsbtFormat
	}

	derivation := TaprootBip32Derivation{
		XOnlyPubKey: xOnlyPubKey,
		LeafHashes:  make([][]byte, int(numHashes)),
	}

	for i := 0; i < int(numHashes); i++ {
		derivation.LeafHashes[i] = make([]byte, 32)
		n, err := reader.Read(derivation.LeafHashes[i])
		if err != nil || n != 32 {
			return nil, ErrInvalidPsbtFormat
		}
	}

	// Extract the remaining bytes from the reader (we don't actually know
	// how many bytes we read due to the compact size integer at the
	// beginning).
	var leftoverBuf bytes.Buffer
	_, err = reader.WriteTo(&leftoverBuf)
	if err != nil {
		return nil, err
	}

	// Read the BIP32 derivation info.
	fingerprint, path, err := readBip32Derivation(leftoverBuf.Bytes())
	if err != nil {
		return nil, err
	}

	derivation.MasterKeyFingerprint = fingerprint
	derivation.Bip32Path = path

	return &derivation, nil
}

// serializeTaprootLeaf serializes a TaprootTapLeafScript to its raw byte representation (script + leaf version)
func serializeTaprootLeafScript(l *TaprootTapLeafScript) ([]byte, error) {
	var buf bytes.Buffer

	// <script> <8-bit uint>
	_, err := buf.Write(l.Script)
	if err != nil {
		return nil, ErrInvalidPsbtFormat
	}

	err = buf.WriteByte(byte(l.LeafVersion))
	if err != nil {
		return nil, ErrInvalidPsbtFormat
	}

	return buf.Bytes(), nil
}

// serializeTaprootScriptSpendSig concatenates xonlypubkey and leafhash of the sig
func serializeTaprootScriptSpendSig(s *TaprootScriptSpendSig) ([]byte, error) {
	var buf bytes.Buffer

	// <xonlypubkey> <leafhash>
	_, err := buf.Write(s.XOnlyPubKey)
	if err != nil {
		return nil, ErrInvalidPsbtFormat
	}

	_, err = buf.Write(s.LeafHash)
	if err != nil {
		return nil, ErrInvalidPsbtFormat
	}

	return buf.Bytes(), nil
}
