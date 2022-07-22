package psetv2_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"log"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulpemventures/go-elements/confidential"
	"github.com/vulpemventures/go-elements/elementsutil"
	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/payment"
	"github.com/vulpemventures/go-elements/psetv2"
	"github.com/vulpemventures/go-elements/taproot"
	"github.com/vulpemventures/go-elements/transaction"
)

var (
	sighashAll = txscript.SigHashAll
)

/*
*	The fixtures for this test have been generated with Elements CLI and
*	demonstrate that this package is able to serialize a partial transaction
* compliant with the Elements implementation.
 */
func TestRoundTrip(t *testing.T) {
	file, _ := ioutil.ReadFile("testdata/roundtrip.json")
	var tests []map[string]interface{}
	json.Unmarshal(file, &tests)

	for _, v := range tests {
		t.Run(v["name"].(string), func(t *testing.T) {
			psetBase64 := v["base64"].(string)

			ptx, err := psetv2.NewPsetFromBase64(psetBase64)
			require.NoError(t, err)

			ptxBase64, err := ptx.ToBase64()
			require.NoError(t, err)
			a, _ := base64.StdEncoding.DecodeString(psetBase64)
			b, _ := base64.StdEncoding.DecodeString(ptxBase64)
			require.Equal(t, b2h(a), b2h(b))
		})
	}
}

func TestBroadcastUnblindedTx(t *testing.T) {
	privkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubkey := privkey.PubKey()
	p2wpkh := payment.FromPublicKey(pubkey, &network.Regtest, nil)
	address, _ := p2wpkh.WitnessPubKeyHash()

	// Fund sender address.
	_, err = faucet(address)
	require.NoError(t, err)
	time.Sleep(time.Second * 3)

	// Retrieve sender utxos.
	utxos, err := unspents(address)
	require.NoError(t, err)

	prevoutIndex := uint32(utxos[0]["vout"].(float64))
	prevoutTxid := utxos[0]["txid"].(string)

	inputArgs := []psetv2.InputArgs{
		{
			TxIndex: prevoutIndex,
			Txid:    prevoutTxid,
		},
	}

	outputArgs := []psetv2.OutputArgs{
		{
			Asset:   lbtc,
			Amount:  60000000,
			Address: "2dwq2ByzMwkJuU7Swbdz51udh1UosBeaYZ2",
		},
		{
			Asset:   lbtc,
			Amount:  39999500,
			Address: address,
		},
		{
			Asset:   lbtc,
			Amount:  500,
			Address: "",
		},
	}

	ptx, err := psetv2.New(inputArgs, outputArgs, 0)
	require.NoError(t, err)

	updater, err := psetv2.NewUpdater(ptx)
	require.NoError(t, err)

	asset, _ := elementsutil.AssetHashToBytes(utxos[0]["asset"].(string))
	value, _ := elementsutil.ValueToBytes(uint64(utxos[0]["value"].(float64)))
	witnessUtxo := transaction.NewTxOutput(asset, value, p2wpkh.WitnessScript)
	err = updater.AddInWitnessUtxo(witnessUtxo, 0)
	require.NoError(t, err)

	prvKeys := []*btcec.PrivateKey{privkey}
	scripts := [][]byte{p2wpkh.Script}
	err = signTransaction(ptx, prvKeys, scripts, true, sighashAll, nil)
	require.NoError(t, err)

	_, err = broadcastTransaction(ptx)
	require.NoError(t, err)
}

func TestBroadcastUnblindedIssuanceTx(t *testing.T) {
	privkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubkey := privkey.PubKey()
	p2wpkh := payment.FromPublicKey(pubkey, &network.Regtest, nil)
	address, _ := p2wpkh.WitnessPubKeyHash()

	// Fund sender address.
	_, err = faucet(address)
	require.NoError(t, err)
	time.Sleep(time.Second * 3)

	// Retrieve sender utxos.
	utxos, err := unspents(address)
	require.NoError(t, err)

	prevoutIndex := uint32(utxos[0]["vout"].(float64))
	prevoutTxid := utxos[0]["txid"].(string)

	inputArgs := []psetv2.InputArgs{
		{
			TxIndex: prevoutIndex,
			Txid:    prevoutTxid,
		},
	}

	outputArgs := []psetv2.OutputArgs{
		{
			Asset:   lbtc,
			Amount:  99999500,
			Address: address,
		},
		{
			Asset:   lbtc,
			Amount:  500,
			Address: "",
		},
	}

	ptx, err := psetv2.New(inputArgs, outputArgs, 0)
	require.NoError(t, err)

	updater, err := psetv2.NewUpdater(ptx)
	require.NoError(t, err)

	asset, _ := elementsutil.AssetHashToBytes(utxos[0]["asset"].(string))
	value, _ := elementsutil.ValueToBytes(uint64(utxos[0]["value"].(float64)))
	witnessUtxo := transaction.NewTxOutput(asset, value, p2wpkh.WitnessScript)
	err = updater.AddInWitnessUtxo(witnessUtxo, 0)
	require.NoError(t, err)

	err = updater.AddInIssuance(psetv2.AddInIssuanceArgs{
		AssetAmount:  1000,
		TokenAmount:  1,
		AssetAddress: address,
		TokenAddress: address,
	})
	require.NoError(t, err)

	prvKeys := []*btcec.PrivateKey{privkey}
	scripts := [][]byte{p2wpkh.Script}
	err = signTransaction(ptx, prvKeys, scripts, true, sighashAll, nil)
	require.NoError(t, err)

	_, err = broadcastTransaction(ptx)
	require.NoError(t, err)
}

func TestBroadcastBlindedTx(t *testing.T) {
	blindingPrivateKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	blindingPublicKey := blindingPrivateKey.PubKey()

	privkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubkey := privkey.PubKey()
	p2wpkh := payment.FromPublicKey(pubkey, &network.Regtest, blindingPublicKey)
	address, _ := p2wpkh.ConfidentialWitnessPubKeyHash()

	// Fund sender address.
	_, err = faucet(address)
	require.NoError(t, err)
	time.Sleep(time.Second * 3)

	// Retrieve sender utxos.
	utxos, err := unspents(address)
	require.NoError(t, err)

	prevoutIndex := uint32(utxos[0]["vout"].(float64))
	prevoutTxid := utxos[0]["txid"].(string)

	inputArgs := []psetv2.InputArgs{
		{
			TxIndex: prevoutIndex,
			Txid:    prevoutTxid,
		},
	}

	outputArgs := []psetv2.OutputArgs{
		{
			Asset:   lbtc,
			Amount:  60000000,
			Address: "2dwq2ByzMwkJuU7Swbdz51udh1UosBeaYZ2",
		},
		{
			Asset:   lbtc,
			Amount:  39999500,
			Address: address,
		},
	}

	ptx, err := psetv2.New(inputArgs, outputArgs, 0)
	require.NoError(t, err)

	updater, err := psetv2.NewUpdater(ptx)
	require.NoError(t, err)

	prevTxHex, err := fetchTx(utxos[0]["txid"].(string))
	require.NoError(t, err)

	prevTx, _ := transaction.NewTxFromHex(prevTxHex)
	assetCommitment := h2b(utxos[0]["assetcommitment"].(string))
	valueCommitment := h2b(utxos[0]["valuecommitment"].(string))
	witnessUtxo := &transaction.TxOutput{
		Asset:           assetCommitment,
		Value:           valueCommitment,
		Script:          p2wpkh.WitnessScript,
		Nonce:           prevTx.Outputs[prevoutIndex].Nonce,
		RangeProof:      prevTx.Outputs[prevoutIndex].RangeProof,
		SurjectionProof: prevTx.Outputs[prevoutIndex].SurjectionProof,
	}
	err = updater.AddInWitnessUtxo(witnessUtxo, 0)
	require.NoError(t, err)

	zkpValidator := confidential.NewZKPValidator()
	zkpGenerator := confidential.NewZKPGeneratorFromBlindingKeys(
		[][]byte{blindingPrivateKey.Serialize()},
		nil,
	)

	ownedInputs, err := zkpGenerator.UnblindInputs(ptx, nil)
	require.NoError(t, err)

	blinder, err := psetv2.NewBlinder(
		ptx, ownedInputs, zkpValidator, zkpGenerator,
	)
	require.NoError(t, err)

	outBlindingArgs, err := zkpGenerator.BlindOutputs(ptx, []uint32{1}, nil)
	require.NoError(t, err)

	err = blinder.BlindLast(nil, outBlindingArgs)
	require.NoError(t, err)

	err = updater.AddOutputs([]psetv2.OutputArgs{
		{
			Asset:   lbtc,
			Amount:  500,
			Address: "",
		},
	})
	require.NoError(t, err)

	prvKeys := []*btcec.PrivateKey{privkey}
	scripts := [][]byte{p2wpkh.Script}
	err = signTransaction(ptx, prvKeys, scripts, true, sighashAll, nil)
	require.NoError(t, err)

	_, err = broadcastTransaction(ptx)
	require.NoError(t, err)
}

func TestBroadcastBlindedTxWithDummyConfidentialOutputs(t *testing.T) {
	blindingPrivateKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	blindingPublicKey := blindingPrivateKey.PubKey()

	privkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubkey := privkey.PubKey()
	p2wpkh := payment.FromPublicKey(pubkey, &network.Regtest, blindingPublicKey)
	address, _ := p2wpkh.ConfidentialWitnessPubKeyHash()
	unconfAddress, _ := p2wpkh.WitnessPubKeyHash()

	// Fund sender address.
	_, err = faucet(address)
	require.NoError(t, err)
	time.Sleep(time.Second * 3)

	// Retrieve sender utxos.
	utxos, err := unspents(address)
	require.NoError(t, err)

	prevoutIndex := uint32(utxos[0]["vout"].(float64))
	prevoutTxid := utxos[0]["txid"].(string)

	inputArgs := []psetv2.InputArgs{
		{
			TxIndex: prevoutIndex,
			Txid:    prevoutTxid,
		},
	}

	outputArgs := []psetv2.OutputArgs{
		{
			Asset:   lbtc,
			Amount:  60000000,
			Address: "2dwq2ByzMwkJuU7Swbdz51udh1UosBeaYZ2",
		},
		{
			Asset:   lbtc,
			Amount:  39999500,
			Address: unconfAddress,
		},
		{
			Asset:   lbtc,
			Amount:  0,
			Address: address,
		},
	}

	ptx, err := psetv2.New(inputArgs, outputArgs, 0)
	require.NoError(t, err)

	updater, err := psetv2.NewUpdater(ptx)
	require.NoError(t, err)

	prevTxHex, err := fetchTx(utxos[0]["txid"].(string))
	require.NoError(t, err)

	prevTx, _ := transaction.NewTxFromHex(prevTxHex)
	assetCommitment := h2b(utxos[0]["assetcommitment"].(string))
	valueCommitment := h2b(utxos[0]["valuecommitment"].(string))
	witnessUtxo := &transaction.TxOutput{
		Asset:           assetCommitment,
		Value:           valueCommitment,
		Script:          p2wpkh.WitnessScript,
		Nonce:           prevTx.Outputs[prevoutIndex].Nonce,
		RangeProof:      prevTx.Outputs[prevoutIndex].RangeProof,
		SurjectionProof: prevTx.Outputs[prevoutIndex].SurjectionProof,
	}
	err = updater.AddInWitnessUtxo(witnessUtxo, 0)
	require.NoError(t, err)

	zkpValidator := confidential.NewZKPValidator()
	zkpGenerator := confidential.NewZKPGeneratorFromBlindingKeys(
		[][]byte{blindingPrivateKey.Serialize()},
		nil,
	)

	ownedInputs, err := zkpGenerator.UnblindInputs(ptx, nil)
	require.NoError(t, err)

	blinder, err := psetv2.NewBlinder(
		ptx, ownedInputs, zkpValidator, zkpGenerator,
	)
	require.NoError(t, err)

	outBlindingArgs, err := zkpGenerator.BlindOutputs(ptx, []uint32{2}, nil)
	require.NoError(t, err)

	err = blinder.BlindLast(nil, outBlindingArgs)
	require.NoError(t, err)

	err = updater.AddOutputs([]psetv2.OutputArgs{
		{
			Asset:   lbtc,
			Amount:  500,
			Address: "",
		},
	})
	require.NoError(t, err)

	prvKeys := []*btcec.PrivateKey{privkey}
	scripts := [][]byte{p2wpkh.Script}
	err = signTransaction(ptx, prvKeys, scripts, true, sighashAll, nil)
	require.NoError(t, err)

	_, err = broadcastTransaction(ptx)
	require.NoError(t, err)
}

func TestBroadcastUnblindedIssuanceTxWithBlindedOutputs(t *testing.T) {
	blindingPrivateKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	blindingPublicKey := blindingPrivateKey.PubKey()

	privkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubkey := privkey.PubKey()
	p2wpkh := payment.FromPublicKey(pubkey, &network.Regtest, blindingPublicKey)
	address, _ := p2wpkh.ConfidentialWitnessPubKeyHash()

	// Fund sender address.
	_, err = faucet(address)
	require.NoError(t, err)
	time.Sleep(time.Second * 3)

	// Retrieve sender utxos.
	utxos, err := unspents(address)
	require.NoError(t, err)

	prevoutIndex := uint32(utxos[0]["vout"].(float64))
	prevoutTxid := utxos[0]["txid"].(string)

	inputArgs := []psetv2.InputArgs{
		{
			TxIndex: prevoutIndex,
			Txid:    prevoutTxid,
		},
	}

	outputArgs := []psetv2.OutputArgs{
		{
			Asset:   lbtc,
			Amount:  99999000,
			Address: address,
		},
		{
			Asset:   lbtc,
			Amount:  1000,
			Address: "",
		},
	}

	ptx, err := psetv2.New(inputArgs, outputArgs, 0)
	require.NoError(t, err)

	updater, err := psetv2.NewUpdater(ptx)
	require.NoError(t, err)

	prevTxHex, err := fetchTx(utxos[0]["txid"].(string))
	require.NoError(t, err)

	prevTx, _ := transaction.NewTxFromHex(prevTxHex)
	assetCommitment := h2b(utxos[0]["assetcommitment"].(string))
	valueCommitment := h2b(utxos[0]["valuecommitment"].(string))
	witnessUtxo := &transaction.TxOutput{
		Asset:           assetCommitment,
		Value:           valueCommitment,
		Script:          p2wpkh.WitnessScript,
		Nonce:           prevTx.Outputs[prevoutIndex].Nonce,
		RangeProof:      prevTx.Outputs[prevoutIndex].RangeProof,
		SurjectionProof: prevTx.Outputs[prevoutIndex].SurjectionProof,
	}
	err = updater.AddInWitnessUtxo(witnessUtxo, 0)
	require.NoError(t, err)

	err = updater.AddInIssuance(psetv2.AddInIssuanceArgs{
		AssetAmount:     1000,
		TokenAmount:     1,
		AssetAddress:    address,
		TokenAddress:    address,
		BlindedIssuance: false,
	})
	require.NoError(t, err)

	zkpValidator := confidential.NewZKPValidator()
	zkpGenerator := confidential.NewZKPGeneratorFromBlindingKeys(
		[][]byte{blindingPrivateKey.Serialize()},
		nil,
	)

	ownedInputs, err := zkpGenerator.UnblindInputs(ptx, nil)
	require.NoError(t, err)

	blinder, err := psetv2.NewBlinder(
		ptx, ownedInputs, zkpValidator, zkpGenerator,
	)
	require.NoError(t, err)

	// For unblinded issuances is enough to specify input index and
	// issuance asset and token (if token amount > 0, like in this case).
	// These are needed only to generate output blinding args.
	// They won't be passed to the blinder role
	inIssuanceBlindingArgs := []psetv2.InputIssuanceBlindingArgs{
		{
			Index:         0,
			IssuanceAsset: ptx.Inputs[0].GetIssuanceAssetHash(),
			IssuanceToken: ptx.Inputs[0].GetIssuanceInflationKeysHash(false),
		},
	}
	outBlindingArgs, err := zkpGenerator.BlindOutputs(ptx, nil, inIssuanceBlindingArgs)
	require.NoError(t, err)

	err = blinder.BlindLast(nil, outBlindingArgs)
	require.NoError(t, err)

	prvKeys := []*btcec.PrivateKey{privkey}
	scripts := [][]byte{p2wpkh.Script}
	err = signTransaction(ptx, prvKeys, scripts, true, sighashAll, nil)
	require.NoError(t, err)

	_, err = broadcastTransaction(ptx)
	require.NoError(t, err)
}

func TestBroadcastBlindedIssuanceTx(t *testing.T) {
	blindingPrivateKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	blindingPublicKey := blindingPrivateKey.PubKey()

	privkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubkey := privkey.PubKey()
	p2wpkh := payment.FromPublicKey(pubkey, &network.Regtest, blindingPublicKey)
	address, _ := p2wpkh.ConfidentialWitnessPubKeyHash()

	// Fund sender address.
	_, err = faucet(address)
	require.NoError(t, err)
	time.Sleep(time.Second * 3)

	// Retrieve sender utxos.
	utxos, err := unspents(address)
	require.NoError(t, err)

	prevoutIndex := uint32(utxos[0]["vout"].(float64))
	prevoutTxid := utxos[0]["txid"].(string)

	inputArgs := []psetv2.InputArgs{
		{
			TxIndex: prevoutIndex,
			Txid:    prevoutTxid,
		},
	}

	outputArgs := []psetv2.OutputArgs{
		{
			Asset:   lbtc,
			Amount:  99999000,
			Address: address,
		},
		{
			Asset:   lbtc,
			Amount:  1000,
			Address: "",
		},
	}

	ptx, err := psetv2.New(inputArgs, outputArgs, 0)
	require.NoError(t, err)

	updater, err := psetv2.NewUpdater(ptx)
	require.NoError(t, err)

	prevTxHex, err := fetchTx(utxos[0]["txid"].(string))
	require.NoError(t, err)

	prevTx, _ := transaction.NewTxFromHex(prevTxHex)
	assetCommitment := h2b(utxos[0]["assetcommitment"].(string))
	valueCommitment := h2b(utxos[0]["valuecommitment"].(string))
	witnessUtxo := &transaction.TxOutput{
		Asset:           assetCommitment,
		Value:           valueCommitment,
		Script:          p2wpkh.WitnessScript,
		Nonce:           prevTx.Outputs[prevoutIndex].Nonce,
		RangeProof:      prevTx.Outputs[prevoutIndex].RangeProof,
		SurjectionProof: prevTx.Outputs[prevoutIndex].SurjectionProof,
	}
	err = updater.AddInWitnessUtxo(witnessUtxo, 0)
	require.NoError(t, err)

	err = updater.AddInIssuance(psetv2.AddInIssuanceArgs{
		AssetAmount:     1000,
		TokenAmount:     1,
		AssetAddress:    address,
		TokenAddress:    address,
		BlindedIssuance: true,
	})
	require.NoError(t, err)

	zkpValidator := confidential.NewZKPValidator()
	zkpGenerator := confidential.NewZKPGeneratorFromBlindingKeys(
		[][]byte{blindingPrivateKey.Serialize()},
		nil,
	)

	ownedInputs, err := zkpGenerator.UnblindInputs(ptx, nil)
	require.NoError(t, err)

	blinder, err := psetv2.NewBlinder(ptx, ownedInputs, zkpValidator, zkpGenerator)
	require.NoError(t, err)

	issuanceKeysByIndex := map[uint32][]byte{
		0: blindingPrivateKey.Serialize(),
	}
	inIssuanceBlindingArgs, err := zkpGenerator.BlindIssuances(ptx, issuanceKeysByIndex)
	require.NoError(t, err)

	outBlindingArgs, err := zkpGenerator.BlindOutputs(ptx, nil, inIssuanceBlindingArgs)
	require.NoError(t, err)

	err = blinder.BlindLast(inIssuanceBlindingArgs, outBlindingArgs)
	require.NoError(t, err)

	prvKeys := []*btcec.PrivateKey{privkey}
	scripts := [][]byte{p2wpkh.Script}
	err = signTransaction(ptx, prvKeys, scripts, true, sighashAll, nil)
	require.NoError(t, err)

	_, err = broadcastTransaction(ptx)
	require.NoError(t, err)
}

// This test shows how 2 parties can create a confiendital swap transaction
// by sharing the blinding private keys.
func TestBroadcastBlindedSwapTx(t *testing.T) {
	aliceBlindingPrivateKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	alicePrivkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	aliceBlindingPublicKey := aliceBlindingPrivateKey.PubKey()
	alicePubkey := alicePrivkey.PubKey()
	aliceP2wpkh := payment.FromPublicKey(alicePubkey, &network.Regtest, aliceBlindingPublicKey)
	aliceAddress, _ := aliceP2wpkh.ConfidentialWitnessPubKeyHash()

	bobBlindingPrivateKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	bobPrivkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	bobBlindingPublicKey := bobBlindingPrivateKey.PubKey()
	bobPubkey := bobPrivkey.PubKey()
	bobP2wpkh := payment.FromPublicKey(bobPubkey, &network.Regtest, bobBlindingPublicKey)
	bobAddress, _ := bobP2wpkh.ConfidentialWitnessPubKeyHash()

	// Send LBTC funds to alice's address.
	_, err = faucet(aliceAddress)
	require.NoError(t, err)

	// Send USDT funds to bob's address.
	_, usdt, err := mint(bobAddress, 1, "", "")
	require.NoError(t, err)
	time.Sleep(time.Second * 3)

	// Retrieve alice's utxos.
	aliceUtxos, err := unspents(aliceAddress)
	require.NoError(t, err)

	// Retrieve bob's utxos.
	bobUtxos, err := unspents(bobAddress)
	require.NoError(t, err)

	alicePrevoutIndex := uint32(aliceUtxos[0]["vout"].(float64))
	alicePrevoutTxid := aliceUtxos[0]["txid"].(string)

	// Alice creates the transaction with her inputs and expected outputs.
	aliceInputArgs := []psetv2.InputArgs{
		{
			TxIndex: alicePrevoutIndex,
			Txid:    alicePrevoutTxid,
		},
	}

	aliceOutputArgs := []psetv2.OutputArgs{
		{
			Asset:   usdt,
			Amount:  50000000,
			Address: aliceAddress,
		},
		{
			Asset:   lbtc,
			Amount:  49999000,
			Address: aliceAddress,
		},
		{
			Asset:   lbtc,
			Amount:  1000,
			Address: "",
		},
	}

	ptx, err := psetv2.New(aliceInputArgs, aliceOutputArgs, 0)
	require.NoError(t, err)

	updater, err := psetv2.NewUpdater(ptx)
	require.NoError(t, err)

	alicePrevTxHex, err := fetchTx(aliceUtxos[0]["txid"].(string))
	require.NoError(t, err)

	alicePrevTx, _ := transaction.NewTxFromHex(alicePrevTxHex)
	aliceAssetCommitment := h2b(aliceUtxos[0]["assetcommitment"].(string))
	aliceValueCommitment := h2b(aliceUtxos[0]["valuecommitment"].(string))
	aliceWitnessUtxo := &transaction.TxOutput{
		Asset:           aliceAssetCommitment,
		Value:           aliceValueCommitment,
		Script:          aliceP2wpkh.WitnessScript,
		Nonce:           alicePrevTx.Outputs[alicePrevoutIndex].Nonce,
		RangeProof:      alicePrevTx.Outputs[alicePrevoutIndex].RangeProof,
		SurjectionProof: alicePrevTx.Outputs[alicePrevoutIndex].SurjectionProof,
	}
	err = updater.AddInWitnessUtxo(aliceWitnessUtxo, 0)
	require.NoError(t, err)

	// Now it's bob's turn to add his input and outputs.
	bobPrevoutIndex := uint32(bobUtxos[0]["vout"].(float64))
	bobPrevoutTxid := bobUtxos[0]["txid"].(string)

	bobInputArgs := []psetv2.InputArgs{
		{
			Txid:    bobPrevoutTxid,
			TxIndex: bobPrevoutIndex,
		},
	}

	err = updater.AddInputs(bobInputArgs)
	require.NoError(t, err)

	bobOutputBlinderIndex := uint32(1)
	bobOutputArgs := []psetv2.OutputArgs{
		{
			Asset:        lbtc,
			Amount:       50000000,
			Address:      bobAddress,
			BlinderIndex: bobOutputBlinderIndex,
		},
		{
			Asset:        usdt,
			Amount:       50000000,
			Address:      bobAddress,
			BlinderIndex: bobOutputBlinderIndex,
		},
	}

	err = updater.AddOutputs(bobOutputArgs)
	require.NoError(t, err)

	bobPrevTxHex, err := fetchTx(bobUtxos[0]["txid"].(string))
	require.NoError(t, err)

	bobPrevTx, _ := transaction.NewTxFromHex(bobPrevTxHex)
	bobAssetCommitment := h2b(bobUtxos[0]["assetcommitment"].(string))
	bobValueCommitment := h2b(bobUtxos[0]["valuecommitment"].(string))
	bobWitnessUtxo := &transaction.TxOutput{
		Asset:           bobAssetCommitment,
		Value:           bobValueCommitment,
		Script:          bobP2wpkh.WitnessScript,
		Nonce:           bobPrevTx.Outputs[bobPrevoutIndex].Nonce,
		RangeProof:      bobPrevTx.Outputs[bobPrevoutIndex].RangeProof,
		SurjectionProof: bobPrevTx.Outputs[bobPrevoutIndex].SurjectionProof,
	}
	err = updater.AddInWitnessUtxo(bobWitnessUtxo, 1)
	require.NoError(t, err)

	// Bob can now blind all outputs with his and alice's blinding private keys.
	zkpValidator := confidential.NewZKPValidator()
	zkpGenerator := confidential.NewZKPGeneratorFromBlindingKeys(
		[][]byte{
			aliceBlindingPrivateKey.Serialize(), bobBlindingPrivateKey.Serialize(),
		},
		nil,
	)

	ownedInputs, err := zkpGenerator.UnblindInputs(ptx, nil)
	require.NoError(t, err)

	blinder, err := psetv2.NewBlinder(
		ptx, ownedInputs, zkpValidator, zkpGenerator,
	)
	require.NoError(t, err)

	outBlindingArgs, err := zkpGenerator.BlindOutputs(ptx, nil, nil)
	require.NoError(t, err)

	// Bob blinds the pset as last blinder.
	err = blinder.BlindLast(nil, outBlindingArgs)
	require.NoError(t, err)

	// Now that blinding is complete, both parties can sign the pset...
	prvKeys := []*btcec.PrivateKey{alicePrivkey, bobPrivkey}
	scripts := [][]byte{aliceP2wpkh.Script, bobP2wpkh.Script}
	err = signTransaction(ptx, prvKeys, scripts, true, sighashAll, nil)
	require.NoError(t, err)

	// ...and broadcast the confidential swap tx to the network.
	_, err = broadcastTransaction(ptx)
	require.NoError(t, err)
}

func TestBroadcastTaprootKeyPset(t *testing.T) {
	alicePrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	internalPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	internalPubKey := internalPrivKey.PubKey()

	blindingKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	checksigSchnorrScript, err := txscript.NewScriptBuilder().AddData(schnorr.SerializePubKey(alicePrivKey.PubKey())).AddOp(txscript.OP_CHECKSIG).Script()
	require.NoError(t, err)

	leaf := taproot.NewBaseTapElementsLeaf(checksigSchnorrScript)
	tree := taproot.AssembleTaprootScriptTree(leaf)

	taprootPay, err := payment.FromTaprootScriptTree(internalPubKey, tree, &network.Regtest, blindingKey.PubKey())
	require.NoError(t, err)

	addr, err := taprootPay.ConfidentialTaprootAddress()
	require.NoError(t, err)

	txID, err := faucet(addr)
	require.NoError(t, err)
	time.Sleep(5 * time.Second)

	faucetTxHex, err := fetchTx(txID)
	require.NoError(t, err)

	faucetTx, err := transaction.NewTxFromHex(faucetTxHex)
	require.NoError(t, err)

	var utxo *transaction.TxOutput
	var vout uint32
	for index, out := range faucetTx.Outputs {
		if bytes.Equal(out.Script, taprootPay.Script) {
			utxo = out
			vout = uint32(index)
			break
		}
	}

	if utxo == nil {
		t.Fatal("could not find utxo")
	}

	lbtc := "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225"

	inputs := []psetv2.InputArgs{
		{
			Txid:    txID,
			TxIndex: vout,
		},
	}

	outputs := []psetv2.OutputArgs{
		{
			Asset:   lbtc,
			Amount:  60000000,
			Address: "el1qq22tykcgulgre5u0u07ug3hg92q295zcylgm6g2swyxd2xzk6jtw9yg2jhswp3a7pm2gf2wenfxn3063mxp8z3u2zjj36sl5a",
		},
		psetv2.OutputArgs{
			Asset:   lbtc,
			Amount:  39999500,
			Address: addr,
		},
		psetv2.OutputArgs{
			Asset:   lbtc,
			Amount:  500,
			Address: "",
		},
	}
	ptx, err := psetv2.New(inputs, outputs, 0)
	require.NoError(t, err)

	updater, err := psetv2.NewUpdater(ptx)
	require.NoError(t, err)

	err = updater.AddInSighashType(txscript.SigHashDefault, 0)
	require.NoError(t, err)

	err = updater.AddInWitnessUtxo(utxo, 0)
	require.NoError(t, err)

	// Add taproot fields to input

	proof, err := tree.FindProof(leaf.TapHash())
	require.NoError(t, err)

	controlBlock := proof.ToControlBlock(internalPubKey)
	controlBlockBytes, err := controlBlock.ToBytes()
	require.NoError(t, err)

	err = updater.AddInTapLeafScript(&psetv2.TaprootTapLeafScript{
		LeafVersion:  proof.LeafVersion,
		Script:       proof.Script,
		ControlBlock: controlBlockBytes,
	}, 0)
	require.NoError(t, err)

	// blind step
	zkpValidator := confidential.NewZKPValidator()
	zkpGenerator := confidential.NewZKPGeneratorFromBlindingKeys(
		[][]byte{
			blindingKey.Serialize(),
		},
		nil,
	)

	ownedInputs, err := zkpGenerator.UnblindInputs(ptx, nil)
	require.NoError(t, err)

	blinder, err := psetv2.NewBlinder(
		ptx, ownedInputs, zkpValidator, zkpGenerator,
	)
	require.NoError(t, err)

	outBlindingArgs, err := zkpGenerator.BlindOutputs(ptx, nil, nil)
	require.NoError(t, err)

	err = blinder.BlindLast(nil, outBlindingArgs)
	require.NoError(t, err)

	// Sign step
	genesisBlockhash, err := chainhash.NewHashFromStr("00902a6b70c2ca83b5d9c815d96a0e2f4202179316970d14ea1847dae5b1ca21")
	require.NoError(t, err)

	preimage, err := ptx.GetTaprootPreimage(0, genesisBlockhash, nil)
	require.NoError(t, err)

	sig, err := schnorr.Sign(internalPrivKey, preimage[:])
	require.NoError(t, err)

	signer, err := psetv2.NewSigner(ptx)
	require.NoError(t, err)

	merkleRoot := taprootPay.Taproot.ScriptTree.RootNode.TapHash()
	err = signer.SignTaprootInputKeyPath(0, sig.Serialize(), schnorr.SerializePubKey(internalPubKey), merkleRoot[:])
	require.NoError(t, err)

	// verify
	valid, err := ptx.ValidateAllSignatures(genesisBlockhash)
	require.NoError(t, err)
	require.True(t, valid)

	// finalize
	err = psetv2.Finalize(ptx, 0)
	require.NoError(t, err)

	signed, err := psetv2.Extract(ptx)
	require.NoError(t, err)

	hex, err := signed.ToHex()
	require.NoError(t, err)
	log.Print(hex)

	txID, err = broadcast(hex)
	require.NoError(t, err)

	assert.NotEmpty(t, txID)
}

func TestBroadcastTapscriptPset(t *testing.T) {
	alicePrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	internalPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	internalPubKey := internalPrivKey.PubKey()

	blindingKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	checksigSchnorrScript, err := txscript.NewScriptBuilder().AddData(schnorr.SerializePubKey(alicePrivKey.PubKey())).AddOp(txscript.OP_CHECKSIG).Script()
	require.NoError(t, err)

	leaf := taproot.NewBaseTapElementsLeaf(checksigSchnorrScript)
	tree := taproot.AssembleTaprootScriptTree(leaf)

	taprootPay, err := payment.FromTaprootScriptTree(internalPubKey, tree, &network.Regtest, blindingKey.PubKey())
	require.NoError(t, err)

	addr, err := taprootPay.ConfidentialTaprootAddress()
	require.NoError(t, err)

	txID, err := faucet(addr)
	require.NoError(t, err)
	time.Sleep(5 * time.Second)

	faucetTxHex, err := fetchTx(txID)
	require.NoError(t, err)

	faucetTx, err := transaction.NewTxFromHex(faucetTxHex)
	require.NoError(t, err)

	var utxo *transaction.TxOutput
	var vout uint32
	for index, out := range faucetTx.Outputs {
		if bytes.Equal(out.Script, taprootPay.Script) {
			utxo = out
			vout = uint32(index)
			break
		}
	}

	if utxo == nil {
		t.Fatal("could not find utxo")
	}

	lbtc := "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225"

	inputs := []psetv2.InputArgs{
		{
			Txid:    txID,
			TxIndex: vout,
		},
	}

	fees := uint64(5000)

	outputs := []psetv2.OutputArgs{
		{
			Asset:   lbtc,
			Amount:  100000000 - fees,
			Address: "el1qq22tykcgulgre5u0u07ug3hg92q295zcylgm6g2swyxd2xzk6jtw9yg2jhswp3a7pm2gf2wenfxn3063mxp8z3u2zjj36sl5a",
		},
		psetv2.OutputArgs{
			Asset:   lbtc,
			Amount:  fees,
			Address: "",
		},
	}
	ptx, err := psetv2.New(inputs, outputs, 0)
	require.NoError(t, err)

	updater, err := psetv2.NewUpdater(ptx)
	require.NoError(t, err)

	err = updater.AddInSighashType(txscript.SigHashDefault, 0)
	require.NoError(t, err)

	err = updater.AddInWitnessUtxo(utxo, 0)
	require.NoError(t, err)

	// Add taproot fields to input

	proof, err := tree.FindProof(leaf.TapHash())
	require.NoError(t, err)

	controlBlock := proof.ToControlBlock(internalPubKey)
	controlBlockBytes, err := controlBlock.ToBytes()
	require.NoError(t, err)

	err = updater.AddInTapLeafScript(&psetv2.TaprootTapLeafScript{
		LeafVersion:  proof.LeafVersion,
		Script:       proof.Script,
		ControlBlock: controlBlockBytes,
	}, 0)
	require.NoError(t, err)

	// blind step
	zkpValidator := confidential.NewZKPValidator()
	zkpGenerator := confidential.NewZKPGeneratorFromBlindingKeys(
		[][]byte{
			blindingKey.Serialize(),
		},
		nil,
	)

	ownedInputs, err := zkpGenerator.UnblindInputs(ptx, nil)
	require.NoError(t, err)

	blinder, err := psetv2.NewBlinder(
		ptx, ownedInputs, zkpValidator, zkpGenerator,
	)
	require.NoError(t, err)

	outBlindingArgs, err := zkpGenerator.BlindOutputs(ptx, nil, nil)
	require.NoError(t, err)

	err = blinder.BlindLast(nil, outBlindingArgs)
	require.NoError(t, err)

	// Sign step
	genesisBlockhash, err := chainhash.NewHashFromStr("00902a6b70c2ca83b5d9c815d96a0e2f4202179316970d14ea1847dae5b1ca21")
	require.NoError(t, err)

	leafHash := leaf.TapHash()
	preimage, err := ptx.GetTaprootPreimage(0, genesisBlockhash, &leafHash)
	require.NoError(t, err)

	sig, err := schnorr.Sign(alicePrivKey, preimage[:])
	require.NoError(t, err)

	require.True(t, sig.Verify(preimage[:], alicePrivKey.PubKey()))

	tapscriptSignature := &psetv2.TaprootScriptSpendSig{
		XOnlyPubKey: schnorr.SerializePubKey(alicePrivKey.PubKey()),
		LeafHash:    leafHash.CloneBytes(),
		Signature:   sig.Serialize(),
		SigHash:     txscript.SigHashDefault,
	}

	signer, err := psetv2.NewSigner(ptx)
	require.NoError(t, err)

	err = signer.SignTaprootInputScriptPath(0, tapscriptSignature)
	require.NoError(t, err)

	// verify
	valid, err := ptx.ValidateAllSignatures(genesisBlockhash)
	require.NoError(t, err)
	require.True(t, valid)

	// finalize
	err = psetv2.Finalize(ptx, 0)
	require.NoError(t, err)

	signed, err := psetv2.Extract(ptx)
	require.NoError(t, err)

	hex, err := signed.ToHex()
	require.NoError(t, err)
	log.Print(hex)

	txID, err = broadcast(hex)
	require.NoError(t, err)

	assert.NotEmpty(t, txID)
}
