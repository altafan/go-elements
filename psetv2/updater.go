// Copyright (c) 2018 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package psetv2

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"

	"github.com/vulpemventures/go-elements/address"
	"github.com/vulpemventures/go-elements/elementsutil"
	"github.com/vulpemventures/go-elements/transaction"
)

const (
	NonConfidentialReissuanceTokenFlag = 0
	ConfidentialReissuanceTokenFlag    = 1
)

var (
	ErrInputIsFinalized                  = fmt.Errorf("input is finalized")
	ErrInputIndexOutOfRange              = fmt.Errorf("provided input index is out of range")
	ErrOutputIndexOutOfRange             = fmt.Errorf("provided output index is out of range")
	ErrInvalidSignatureForInput          = fmt.Errorf("signature does not correspond to this input")
	ErrInIssuanceMissingAssetAddress     = fmt.Errorf("missing destination address for asset to (re)issue")
	ErrInIssuanceMissingTokenAddress     = fmt.Errorf("missing destination address for token to (re)issue")
	ErrInIssuanceAddressesMismatch       = fmt.Errorf("asset and token destination addresses must both be confidential or non-confidential")
	ErrPsetMissingInputForIssuance       = fmt.Errorf("pset must contain at least one input to add issuance to")
	ErrPsetMissingEmptyInputsForIssuance = fmt.Errorf("transaction does not contain any input with empty issuance")
	ErrInReissuanceMissingPrevout        = fmt.Errorf("either WitnessUtxo or NonWitnessUtxo must be defined")
	ErrInReissuanceInvalidTokenBlinder   = fmt.Errorf("invalid token prevout blinder length")
	ErrInReissuanceZeroTokenBlinder      = fmt.Errorf("token prevout blinder must not be a zero blinder")
	ErrInReissuanceInvalidAssetAmount    = fmt.Errorf("invalid reissuance asset amount")
	ErrInReissuanceInvalidTokenAmount    = fmt.Errorf("invalid reissuance token amount")
	ErrInInvalidTapLeafControlBlock      = fmt.Errorf("invalid tap leaf control block")
	ErrInInvalidSchnorrSignature         = fmt.Errorf("invalid schnorr signature")
	ErrInInputHasTapKeySig               = fmt.Errorf("input already has a tap key signature")
	ErrInInvalidTapScriptSig             = fmt.Errorf("invalid taproot script sig")
	ErrInInvalidTapInternalKey           = fmt.Errorf("invalid taproot internal key")
	ErrOutHasTapTree                     = fmt.Errorf("output already has a tap tree")
	ErrOutHasTapInternalKey              = fmt.Errorf("output already has a tap internal key")
)

// Updater encapsulates the role 'Updater' as specified in BIP174; it accepts
// Psbt structs and has methods to add fields to the inputs and outputs.
type Updater struct {
	Pset *Pset
}

// NewUpdater returns a new instance of Updater, if the passed Psbt struct is
// in a valid form, else an error.a
func NewUpdater(p *Pset) (*Updater, error) {
	if err := p.SanityCheck(); err != nil {
		return nil, fmt.Errorf("invalid pset: %s", err)
	}

	return &Updater{Pset: p}, nil
}

// AddInputs adds the provided inputs to the Pset
func (u *Updater) AddInputs(inputs []InputArgs) error {
	for i, in := range inputs {
		if err := in.validate(); err != nil {
			return fmt.Errorf("invalid input %d: %s", i, err)
		}
	}

	p := u.Pset.Copy()

	for _, in := range inputs {
		if err := p.addInput(in.toPartialInput()); err != nil {
			return fmt.Errorf("faile to add input: %s", err)
		}
	}

	u.Pset.Global = p.Global
	u.Pset.Inputs = p.Inputs
	u.Pset.Outputs = p.Outputs
	return u.Pset.SanityCheck()
}

// AddOutput adds the provided outputs to the Pset
func (u *Updater) AddOutputs(outputs []OutputArgs) error {
	for i, out := range outputs {
		if err := out.validate(); err != nil {
			return fmt.Errorf("invalid output args %d: %s", i, err)
		}
	}

	p := u.Pset.Copy()

	for _, out := range outputs {
		if err := p.addOutput(out.toPartialOutput()); err != nil {
			return fmt.Errorf("failed to add output: %s", err)
		}
	}

	u.Pset.Global = p.Global
	u.Pset.Inputs = p.Inputs
	u.Pset.Outputs = p.Outputs
	return u.Pset.SanityCheck()
}

// AddInNonWitnessUtxo adds the utxo information for an input which is
// non-witness. This requires provision of a full transaction (which is the
// source of the corresponding prevOut), and the input index. If addition of
// this key-value pair to the Psbt fails, an error is returned.
func (u *Updater) AddInNonWitnessUtxo(inIndex int, tx *transaction.Transaction) error {
	if inIndex > len(u.Pset.Inputs)-1 {
		return ErrInputIndexOutOfRange
	}
	txid := tx.TxHash()
	if !bytes.Equal(txid[:], u.Pset.Inputs[inIndex].PreviousTxid) {
		return ErrInInvalidNonWitnessUtxo
	}
	u.Pset.Inputs[inIndex].NonWitnessUtxo = tx

	return u.Pset.SanityCheck()
}

// AddInWitnessUtxo adds the utxo information for an input which is witness.
// This requires provision of a full transaction *output* (which is the source
// of the corresponding prevOut); not the full transaction because BIP143 means
// the output information is sufficient, and the input index. If addition of
// this key-value pair to the Psbt fails, an error is returned.
func (u *Updater) AddInWitnessUtxo(txout *transaction.TxOutput, inIndex int) error {
	if inIndex > len(u.Pset.Inputs)-1 {
		return ErrInputIndexOutOfRange
	}
	u.Pset.Inputs[inIndex].WitnessUtxo = txout

	return u.Pset.SanityCheck()
}

// AddInRedeemScript adds the redeem script information for an input.  The
// redeem script is passed serialized, as a byte slice, along with the index of
// the input. An error is returned if addition of this key-value pair to the
// Psbt fails.
func (u *Updater) AddInRedeemScript(redeemScript []byte, inIndex int) error {
	if inIndex > len(u.Pset.Inputs)-1 {
		return ErrInputIndexOutOfRange
	}
	u.Pset.Inputs[inIndex].RedeemScript = redeemScript

	return u.Pset.SanityCheck()
}

// AddInWitnessScript adds the witness script information for an input.  The
// witness script is passed serialized, as a byte slice, along with the index
// of the input. An error is returned if addition of this key-value pair to the
// Psbt fails.
func (u *Updater) AddInWitnessScript(witnessScript []byte, inIndex int) error {
	if inIndex > len(u.Pset.Inputs)-1 {
		return ErrInputIndexOutOfRange
	}
	u.Pset.Inputs[inIndex].WitnessScript = witnessScript

	return u.Pset.SanityCheck()
}

// AddInBip32Derivation takes a master key fingerprint as defined in BIP32, a
// BIP32 path as a slice of uint32 values, and a serialized pubkey as a byte
// slice, along with the integer index of the input, and inserts this data into
// that input.
//
// NOTE: This can be called multiple times for the same input.  An error is
// returned if addition of this key-value pair to the Psbt fails.
func (u *Updater) AddInBip32Derivation(
	masterKeyFingerprint uint32, bip32Path []uint32, pubKeyData []byte,
	inIndex int,
) error {
	if inIndex > len(u.Pset.Inputs)-1 {
		return ErrInputIndexOutOfRange
	}

	bip32Derivation := DerivationPathWithPubKey{
		PubKey:               pubKeyData,
		MasterKeyFingerprint: masterKeyFingerprint,
		Bip32Path:            bip32Path,
	}

	if !validatePubkey(bip32Derivation.PubKey) {
		return ErrInvalidPsbtFormat
	}

	// Don't allow duplicate keys
	for _, x := range u.Pset.Inputs[inIndex].Bip32Derivation {
		if bytes.Equal(x.PubKey, bip32Derivation.PubKey) {
			return ErrDuplicateKey
		}
	}

	u.Pset.Inputs[inIndex].Bip32Derivation = append(
		u.Pset.Inputs[inIndex].Bip32Derivation, bip32Derivation,
	)

	return u.Pset.SanityCheck()
}

// AddInSighashType adds the sighash type information for an input.  The
// sighash type is passed as a 32 bit unsigned integer, along with the index
// for the input. .
func (u *Updater) AddInSighashType(
	sighashType txscript.SigHashType, inIndex int,
) error {
	if inIndex > len(u.Pset.Inputs)-1 {
		return ErrInputIndexOutOfRange
	}

	u.Pset.Inputs[inIndex].SigHashType = sighashType
	return u.Pset.SanityCheck()
}

// AddInIssuanceArgs is a struct encapsulating all the issuance data that
// can be attached to any specific transaction of the PSBT.
type AddInIssuanceArgs struct {
	Precision       uint
	Contract        *transaction.IssuanceContract
	AssetAmount     uint64
	TokenAmount     uint64
	AssetAddress    string
	TokenAddress    string
	BlindedIssuance bool
}

func (arg AddInIssuanceArgs) validate() error {
	if _, err := transaction.NewTxIssuance(
		arg.AssetAmount, arg.TokenAmount, arg.Precision, arg.Contract,
	); err != nil {
		return err
	}

	if len(arg.AssetAddress) <= 0 {
		return ErrInIssuanceMissingAssetAddress
	}

	if _, err := address.DecodeType(arg.AssetAddress); err != nil {
		return fmt.Errorf("invalid issuance asset address: %s", err)
	}

	if arg.TokenAmount > 0 {
		if len(arg.TokenAddress) <= 0 {
			return ErrInIssuanceMissingTokenAddress
		}
		if _, err := address.DecodeType(arg.TokenAddress); err != nil {
			return fmt.Errorf("invalid issuance token address: %s", err)
		}
	}
	if !arg.matchAddressTypes() {
		return ErrInIssuanceAddressesMismatch
	}

	return nil
}

func (arg AddInIssuanceArgs) matchAddressTypes() bool {
	if len(arg.TokenAddress) <= 0 {
		return true
	}

	a, _ := address.IsConfidential(arg.AssetAddress)
	b, _ := address.IsConfidential(arg.TokenAddress)
	return a == b
}

func (arg AddInIssuanceArgs) tokenFlag() uint {
	if arg.BlindedIssuance {
		return uint(ConfidentialReissuanceTokenFlag)
	}
	return uint(NonConfidentialReissuanceTokenFlag)
}

// AddInIssuance adds an unblinded issuance to the transaction
func (u *Updater) AddInIssuance(arg AddInIssuanceArgs) error {
	if err := arg.validate(); err != nil {
		return err
	}

	if len(u.Pset.Inputs) == 0 {
		return ErrPsetMissingInputForIssuance
	}

	prevoutIndex, prevoutHash, inputIndex := findInputWithEmptyIssuance(u.Pset)
	if inputIndex < 0 {
		return ErrPsetMissingEmptyInputsForIssuance
	}

	p := u.Pset.Copy()

	issuance, _ := transaction.NewTxIssuance(
		arg.AssetAmount,
		arg.TokenAmount,
		arg.Precision,
		arg.Contract,
	)

	if err := issuance.GenerateEntropy(prevoutHash, prevoutIndex); err != nil {
		return err
	}

	p.Inputs[inputIndex].IssuanceAssetEntropy = issuance.ContractHash
	p.Inputs[inputIndex].IssuanceValue = arg.AssetAmount
	p.Inputs[inputIndex].IssuanceInflationKeys = arg.TokenAmount
	p.Inputs[inputIndex].IssuanceBlindingNonce = issuance.TxIssuance.AssetBlindingNonce

	rawAsset, _ := issuance.GenerateAsset()
	// prepend with a 0x01 prefix
	rawAsset = append([]byte{0x01}, rawAsset...)
	issuanceAsset := elementsutil.AssetHashFromBytes(rawAsset)
	issuanceOut := OutputArgs{
		Asset:   issuanceAsset,
		Amount:  arg.AssetAmount,
		Address: arg.AssetAddress,
	}
	out := issuanceOut.toPartialOutput()
	if out.NeedsBlinding() {
		inIndex := uint32(inputIndex)
		out.BlinderIndex = inIndex
	}
	if err := p.addOutput(out); err != nil {
		return err
	}

	if arg.TokenAmount > 0 {
		rawAsset, _ := issuance.GenerateReissuanceToken(arg.tokenFlag())
		rawAsset = append([]byte{byte(1)}, rawAsset...)
		tokenAsset := elementsutil.AssetHashFromBytes(rawAsset)
		tokenOut := OutputArgs{
			Asset:   tokenAsset,
			Amount:  arg.TokenAmount,
			Address: arg.TokenAddress,
		}
		out := tokenOut.toPartialOutput()
		if out.NeedsBlinding() {
			inIndex := uint32(inputIndex)
			out.BlinderIndex = inIndex
		}
		if err := p.addOutput(out); err != nil {
			return err
		}
	}

	u.Pset.Global = p.Global
	u.Pset.Inputs = p.Inputs
	u.Pset.Outputs = p.Outputs
	return u.Pset.SanityCheck()
}

// AddInReissuanceArgs defines the mandatory fields that one needs to pass to
// the AddInReissuance method of the *Updater type
// 		PrevOutHash: the prevout hash of the token that will be added as input to the tx
//		PrevOutIndex: the prevout index of the token that will be added as input to the tx
//		PrevOutBlinder: the asset blinder used to blind the prevout token
//		WitnessUtxo: the prevout token in case it is a witness one
//		NonWitnessUtxo: the prevout tx that include the token output in case it is a non-witness one
//		Entropy: the entropy used to generate token and asset
//		AssetAmount: the amount of asset to re-issue
//		TokenAmount: the same unblinded amount of the prevout token
//		AssetAddress: the destination address of the re-issuing asset
//		TokenAddress: the destination address of the re-issuance token
type AddInReissuanceArgs struct {
	TokenPrevOut        InputArgs
	TokenPrevOutBlinder []byte
	WitnessUtxo         *transaction.TxOutput
	NonWitnessUtxo      *transaction.Transaction
	Entropy             string
	AssetAmount         uint64
	AssetAddress        string
	TokenAmount         uint64
	TokenAddress        string
}

func (arg AddInReissuanceArgs) validate() error {
	if arg.WitnessUtxo == nil && arg.NonWitnessUtxo == nil {
		return ErrInReissuanceMissingPrevout
	}

	if err := arg.TokenPrevOut.validate(); err != nil {
		return fmt.Errorf("invalid token prevout: %s", err)
	}

	if arg.NonWitnessUtxo != nil {
		hash := arg.NonWitnessUtxo.TxHash()
		if elementsutil.TxIDFromBytes(hash[:]) != arg.TokenPrevOut.Txid {
			return ErrInInvalidNonWitnessUtxo
		}
	}

	// it's mandatory for the token prevout to be confidential. This because the
	// prevout value blinder will be used as the reissuance's blinding nonce to
	// prove that the spender actually owns and can unblind the token output.
	if !arg.isPrevoutConfidential() {
		return fmt.Errorf(
			"token prevout must be confidential. You must blind your token by " +
				"sending it to yourself in a confidential transaction if you want " +
				"be able to reissue the relative asset",
		)
	}

	if len(arg.TokenPrevOutBlinder) != 32 {
		return ErrInReissuanceInvalidTokenBlinder
	}
	if bytes.Equal(arg.TokenPrevOutBlinder, zeroBlinder) {
		return ErrInReissuanceZeroTokenBlinder
	}

	if buf, err := hex.DecodeString(arg.Entropy); err != nil || len(buf) != 32 {
		return ErrInInvalidIssuanceAssetEntropy
	}

	if arg.AssetAmount == 0 {
		return ErrInReissuanceInvalidAssetAmount
	}

	if arg.TokenAmount == 0 {
		return ErrInReissuanceInvalidTokenAmount
	}

	if len(arg.AssetAddress) <= 0 {
		return ErrInIssuanceMissingAssetAddress
	}
	if _, err := address.DecodeType(arg.AssetAddress); err != nil {
		return fmt.Errorf("invalid reissuance asset address: %s", err)
	}
	if len(arg.TokenAddress) <= 0 {
		return ErrInIssuanceMissingTokenAddress
	}
	if _, err := address.DecodeType(arg.TokenAddress); err != nil {
		return fmt.Errorf("invalid reissuance token address: %s", err)
	}
	if !arg.areAddressesConfidential() {
		return fmt.Errorf("asset and token address must be both confidential")
	}

	return nil
}

func (arg AddInReissuanceArgs) isPrevoutConfidential() bool {
	if arg.WitnessUtxo != nil {
		return arg.WitnessUtxo.IsConfidential()
	}
	return arg.NonWitnessUtxo.Outputs[arg.TokenPrevOut.TxIndex].IsConfidential()
}

func (arg AddInReissuanceArgs) areAddressesConfidential() bool {
	a, _ := address.IsConfidential(arg.AssetAddress)
	b, _ := address.IsConfidential(arg.TokenAddress)
	return a && b
}

// AddInReissuance takes care of adding an input (the prevout token) and 2
// outputs to the partial transaction. It also creates a new (re)issuance with
// the provided entropy, blinder and amounts and attaches it to the new input.
// NOTE: This transaction must be blinded later so that a new token blinding
// nonce is generated for the new token output
func (u *Updater) AddInReissuance(arg AddInReissuanceArgs) error {
	if err := arg.validate(); err != nil {
		return err
	}

	if len(u.Pset.Inputs) == 0 {
		return fmt.Errorf(
			"transaction must contain at least one input before adding a reissuance",
		)
	}

	p := u.Pset.Copy()

	// add input
	if err := p.addInput(arg.TokenPrevOut.toPartialInput()); err != nil {
		return err
	}
	inputIndex := int(p.Global.InputCount)
	if arg.WitnessUtxo != nil {
		if err := u.AddInWitnessUtxo(arg.WitnessUtxo, inputIndex); err != nil {
			return err
		}
	} else {
		if err := u.AddInNonWitnessUtxo(inputIndex, arg.NonWitnessUtxo); err != nil {
			return err
		}
	}

	entropy, _ := hex.DecodeString(arg.Entropy)
	entropy = elementsutil.ReverseBytes(entropy)
	issuance := transaction.NewTxIssuanceFromEntropy(entropy)

	rawAsset, _ := issuance.GenerateAsset()
	rawAsset = append([]byte{0x01}, rawAsset...)
	reissuedAsset := elementsutil.AssetHashFromBytes(rawAsset)
	reissuanceOut := OutputArgs{
		Asset:   reissuedAsset,
		Amount:  arg.AssetAmount,
		Address: arg.AssetAddress,
	}
	out := reissuanceOut.toPartialOutput()
	if out.NeedsBlinding() {
		out.BlinderIndex = arg.TokenPrevOut.TxIndex
	}
	if err := p.addOutput(out); err != nil {
		return err
	}

	rawAsset, _ = issuance.GenerateReissuanceToken(
		ConfidentialReissuanceTokenFlag,
	)
	rawAsset = append([]byte{0x01}, rawAsset...)
	tokenAsset := elementsutil.AssetHashFromBytes(rawAsset)
	tokenOut := OutputArgs{
		Asset:   tokenAsset,
		Amount:  arg.TokenAmount,
		Address: arg.TokenAddress,
	}
	out = tokenOut.toPartialOutput()
	if out.NeedsBlinding() {
		out.BlinderIndex = arg.TokenPrevOut.TxIndex
	}
	if err := p.addOutput(out); err != nil {
		return err
	}

	// add the (re)issuance to the token input. The token amount of the issuance
	// must not be defined for reissunces.
	p.Inputs[inputIndex].IssuanceAssetEntropy = issuance.ContractHash
	p.Inputs[inputIndex].IssuanceValue = arg.AssetAmount
	p.Inputs[inputIndex].IssuanceBlindingNonce = arg.TokenPrevOutBlinder

	u.Pset.Global = p.Global
	u.Pset.Inputs = p.Inputs
	u.Pset.Outputs = p.Outputs
	return u.Pset.SanityCheck()
}

// AddOutBip32Derivation takes a master key fingerprint as defined in BIP32, a
// BIP32 path as a slice of uint32 values, and a serialized pubkey as a byte
// slice, along with the integer index of the output, and inserts this data
// into that output.
//
// NOTE: That this can be called multiple times for the same output.  An error
// is returned if addition of this key-value pair to the Psbt fails.
func (u *Updater) AddOutBip32Derivation(outIndex int, bip32Derivation DerivationPathWithPubKey) error {
	if outIndex > len(u.Pset.Outputs)-1 {
		return ErrOutputIndexOutOfRange
	}

	if !validatePubkey(bip32Derivation.PubKey) {
		return ErrInvalidPsbtFormat
	}

	// Don't allow duplicate keys
	for _, x := range u.Pset.Outputs[outIndex].Bip32Derivation {
		if bytes.Equal(x.PubKey, bip32Derivation.PubKey) {
			return ErrDuplicateKey
		}
	}

	u.Pset.Outputs[outIndex].Bip32Derivation = append(
		u.Pset.Outputs[outIndex].Bip32Derivation, bip32Derivation,
	)

	return u.Pset.SanityCheck()
}

// AddOutRedeemScript takes a redeem script as a byte slice and appends it to
// the output at index outIndex.
func (u *Updater) AddOutRedeemScript(redeemScript []byte, outIndex int) error {
	if outIndex > len(u.Pset.Outputs)-1 {
		return ErrOutputIndexOutOfRange
	}

	u.Pset.Outputs[outIndex].RedeemScript = redeemScript
	return u.Pset.SanityCheck()
}

// AddOutWitnessScript takes a witness script as a byte slice and appends it to
// the output at index outIndex.
func (u *Updater) AddOutWitnessScript(witnessScript []byte, outIndex int) error {
	if outIndex > len(u.Pset.Outputs)-1 {
		return ErrOutputIndexOutOfRange
	}

	u.Pset.Outputs[outIndex].WitnessScript = witnessScript
	return u.Pset.SanityCheck()
}

// addPartialSignature allows the Updater role to insert fields of type partial
// signature into a Pset, consisting of both the pubkey (as keydata) and the
// ECDSA signature (as value).  Note that the Signer role is encapsulated in
// this function; signatures are only allowed to be added that follow the
// sanity-check on signing rules explained in the BIP under `Signer`; if the
// rules are not satisfied, an ErrInvalidSignatureForInput is returned.
//
// NOTE: This function does *not* validate the ECDSA signature itself.
func (u *Updater) addPartialSignature(inIndex int, sig, pubkey []byte) error {
	if inIndex > len(u.Pset.Inputs)-1 {
		return ErrInputIndexOutOfRange
	}

	partialSig := PartialSig{
		PubKey: pubkey, Signature: sig,
	}

	// First validate the passed (sig, pub).
	if !partialSig.checkValid() {
		return ErrInvalidPsbtFormat
	}

	input := u.Pset.Inputs[inIndex]

	// First check; don't add duplicates.
	for _, x := range input.PartialSigs {
		if bytes.Equal(x.PubKey, partialSig.PubKey) {
			return ErrDuplicateKey
		}
	}

	// Next, we perform a series of additional sanity checks.
	if input.NonWitnessUtxo != nil {
		if txHash := input.NonWitnessUtxo.TxHash(); !bytes.Equal(txHash[:], input.PreviousTxid) {
			return ErrInvalidSignatureForInput
		}

		// To validate that the redeem script matches, we must pull out
		// the scriptPubKey of the corresponding output and compare
		// that with the P2SH scriptPubKey that is generated by
		// redeemScript.
		if input.RedeemScript != nil {
			outIndex := input.PreviousTxIndex
			scriptPubKey := input.NonWitnessUtxo.Outputs[outIndex].Script
			scriptHash := btcutil.Hash160(input.RedeemScript)

			scriptHashScript, err := txscript.NewScriptBuilder().
				AddOp(txscript.OP_HASH160).
				AddData(scriptHash).
				AddOp(txscript.OP_EQUAL).
				Script()
			if err != nil {
				return err
			}

			if !bytes.Equal(scriptHashScript, scriptPubKey) {
				return ErrInvalidSignatureForInput
			}
		}
	} else if input.WitnessUtxo != nil {
		scriptPubKey := input.WitnessUtxo.Script

		var script []byte
		if input.RedeemScript != nil {
			scriptHash := btcutil.Hash160(input.RedeemScript)
			scriptHashScript, err := txscript.NewScriptBuilder().
				AddOp(txscript.OP_HASH160).
				AddData(scriptHash).
				AddOp(txscript.OP_EQUAL).
				Script()
			if err != nil {
				return err
			}

			if !bytes.Equal(scriptHashScript, scriptPubKey) {
				return ErrInvalidSignatureForInput
			}

			script = input.RedeemScript
		} else {
			script = scriptPubKey
		}

		// If a witnessScript field is present, this is a P2WSH,
		// whether nested or not (that is handled by the assignment to
		// `script` above); in that case, sanity check that `script` is
		// the p2wsh of witnessScript. Contrariwise, if no
		// witnessScript field is present, this will be signed as
		// p2wkh.
		if input.WitnessScript != nil {
			witnessScriptHash := sha256.Sum256(input.WitnessScript)
			witnessScriptHashScript, err := txscript.NewScriptBuilder().
				AddOp(txscript.OP_0).
				AddData(witnessScriptHash[:]).
				Script()
			if err != nil {
				return err
			}

			if !bytes.Equal(script, witnessScriptHashScript[:]) {
				return ErrInvalidSignatureForInput
			}
		} else {
			// Otherwise, this is a p2wkh input.
			pubkeyHash := btcutil.Hash160(pubkey)
			pubkeyHashScript, err := txscript.NewScriptBuilder().
				AddOp(txscript.OP_0).
				AddData(pubkeyHash).
				Script()
			if err != nil {
				return err
			}

			// Validate that we're able to properly reconstruct the
			// witness program.
			if !bytes.Equal(pubkeyHashScript, script) {
				return ErrInvalidSignatureForInput
			}
		}
	} else {

		// Attaching signature without utxo field is not allowed.
		return ErrInvalidPsbtFormat
	}

	u.Pset.Inputs[inIndex].PartialSigs = append(
		u.Pset.Inputs[inIndex].PartialSigs, partialSig,
	)

	return u.Pset.SanityCheck()
}

// nonWitnessToWitness extracts the TxOut from the existing NonWitnessUtxo
// field in the given PSBT input and sets it as type witness by replacing the
// NonWitnessUtxo field with a WitnessUtxo field. See
// https://github.com/bitcoin/bitcoin/pull/14197.
func (u *Updater) nonWitnessToWitness(inIndex int) error {
	if inIndex > len(u.Pset.Inputs)-1 {
		return ErrInputIndexOutOfRange
	}

	outIndex := u.Pset.Inputs[inIndex].PreviousTxIndex
	txout := u.Pset.Inputs[inIndex].NonWitnessUtxo.Outputs[outIndex]

	// Remove the non-witness first, else sanity check will not pass:
	u.Pset.Inputs[inIndex].NonWitnessUtxo = nil

	return u.AddInWitnessUtxo(txout, inIndex)
}

func findInputWithEmptyIssuance(p *Pset) (uint32, []byte, int) {
	for i, in := range p.Inputs {
		if in.IssuanceValue == 0 {
			return in.PreviousTxIndex, in.PreviousTxid, i
		}
	}
	return 0, nil, -1
}

func (u *Updater) validateInIndex(inIndex int) bool {
	return inIndex <= len(u.Pset.Inputs)-1
}

func (u *Updater) validateOutIndex(outIndex int) bool {
	return outIndex <= len(u.Pset.Outputs)-1
}

// AddInTapLeafScript adds a new leaf to the pset input
func (u *Updater) AddInTapLeafScript(leaf *TaprootTapLeafScript, inIndex int) error {
	if !u.validateInIndex(inIndex) {
		return ErrInputIndexOutOfRange
	}

	if !validateControlBlock(leaf.ControlBlock) {
		return ErrInInvalidTapLeafControlBlock
	}

	u.Pset.Inputs[inIndex].TaprootLeafScript = append(u.Pset.Inputs[inIndex].TaprootLeafScript, leaf)
	return u.Pset.SanityCheck()
}

// AddInTapInternalKey adds the xonly public key as internal taproot key to the input
func (u *Updater) AddInTapInternalKey(internalXOnlyPublicKey []byte, inIndex int) error {
	if !u.validateInIndex(inIndex) {
		return ErrInputIndexOutOfRange
	}

	if !validateXOnlyPubkey(internalXOnlyPublicKey) {
		return ErrInInvalidTapInternalKey
	}

	u.Pset.Inputs[inIndex].TaprootInternalKey = internalXOnlyPublicKey
	return u.Pset.SanityCheck()
}

// AddInTapMerkleRoot adds the taproot script merkle root to the input
func (u *Updater) AddInTapMerkleRoot(merkleRoot *chainhash.Hash, inIndex int) error {
	merkleRootBytes := merkleRoot.CloneBytes()

	if !u.validateInIndex(inIndex) {
		return ErrInputIndexOutOfRange
	}

	u.Pset.Inputs[inIndex].TaprootMerkleRoot = merkleRootBytes
	return u.Pset.SanityCheck()
}

// AddInTapBip32Derivation adds the taproot derivation struct to the input
func (u *Updater) AddInTapBip32Derivation(taprootDerivation *TaprootBip32Derivation, inIndex int) error {
	if !u.validateInIndex(inIndex) {
		return ErrInputIndexOutOfRange
	}

	u.Pset.Inputs[inIndex].TaprootBip32Derivation = append(u.Pset.Inputs[inIndex].TaprootBip32Derivation, taprootDerivation)
	return u.Pset.SanityCheck()
}

// addInTapKeySig adds the key-spend signature to the pset input, it fails if a tapkeysig is already set up
// does not validate the signature with the sighash message
func (u *Updater) addInTapKeySig(sig []byte, inIndex int) error {
	if !u.validateInIndex(inIndex) {
		return ErrInputIndexOutOfRange
	}

	if u.Pset.Inputs[inIndex].TaprootKeySpendSig != nil {
		return ErrInInputHasTapKeySig
	}

	if !validateSchnorrSignature(sig[:schnorrSigMinLength]) {
		return ErrInInvalidSchnorrSignature
	}

	u.Pset.Inputs[inIndex].TaprootKeySpendSig = sig
	return u.Pset.SanityCheck()
}

// addInTapScriptSig adds a tapscript signature to the pset input
// does not validate the signature with the sighash message
func (u *Updater) addInTapScriptSig(sig *TaprootScriptSpendSig, inIndex int) error {
	if !u.validateInIndex(inIndex) {
		return ErrInputIndexOutOfRange
	}

	if !(validateSchnorrSignature(sig.Signature) && validateXOnlyPubkey(sig.XOnlyPubKey)) {
		return ErrInInvalidTapScriptSig
	}

	u.Pset.Inputs[inIndex].TaprootScriptSpendSig = append(u.Pset.Inputs[inIndex].TaprootScriptSpendSig, sig)
	return u.Pset.SanityCheck()
}

// AddOutTapInternalKey adds the xonly internal public key to the taproot output
func (u *Updater) AddOutTapInternalKey(outIndex int, tapInternalKey []byte) error {
	if !u.validateOutIndex(outIndex) {
		return ErrOutputIndexOutOfRange
	}

	if u.Pset.Outputs[outIndex].TaprootInternalKey != nil {
		return ErrOutHasTapInternalKey
	}

	u.Pset.Outputs[outIndex].TaprootInternalKey = tapInternalKey
	return u.Pset.SanityCheck()
}

// AddOutTapTree adds the merkle root of the taproot script tree to the output
func (u *Updater) AddOutTapTree(outIndex int, tree []byte) error {
	if !u.validateOutIndex(outIndex) {
		return ErrOutputIndexOutOfRange
	}

	if u.Pset.Outputs[outIndex].TaprootTapTree != nil {
		return ErrOutHasTapTree
	}

	u.Pset.Outputs[outIndex].TaprootTapTree = tree
	return u.Pset.SanityCheck()
}

// AddOutTapBip32Derivation adds a taproot bip32 derivation struct to the output
func (u *Updater) AddOutTapBip32Derivation(derivation *TaprootBip32Derivation, outIndex int) error {
	if !u.validateOutIndex(outIndex) {
		return ErrOutputIndexOutOfRange
	}

	u.Pset.Outputs[outIndex].TaprootBip32Derivation = append(u.Pset.Outputs[outIndex].TaprootBip32Derivation, derivation)
	return u.Pset.SanityCheck()
}
