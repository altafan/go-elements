package pset

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"testing"

	"github.com/btcsuite/btcd/txscript"
	"github.com/stretchr/testify/assert"
	"github.com/vulpemventures/go-elements/confidential"
	"github.com/vulpemventures/go-elements/internal/bufferutil"
	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/transaction"
)

func TestUpdater(t *testing.T) {
	file, err := ioutil.ReadFile("data/updater.json")
	if err != nil {
		t.Fatal(err)
	}
	var tests []map[string]interface{}
	err = json.Unmarshal(file, &tests)

	for _, v := range tests {
		p, err := NewPsetFromBase64(v["base64"].(string))
		if err != nil {
			t.Fatal(err)
		}
		updater, err := NewUpdater(p)

		for inIndex, vIn := range v["inputs"].([]interface{}) {
			in := vIn.(map[string]interface{})
			if in["nonWitnessUtxo"] != nil {
				tx, err := transaction.NewTxFromHex(in["nonWitnessUtxo"].(string))
				if err != nil {
					t.Fatal(err)
				}
				updater.AddInNonWitnessUtxo(tx, inIndex)
			} else {
				wu := in["witnessUtxo"].(map[string]interface{})
				asset, _ := hex.DecodeString(wu["asset"].(string))
				asset = append([]byte{0x01}, bufferutil.ReverseBytes(asset)...)
				script, _ := hex.DecodeString(wu["script"].(string))
				value, _ := confidential.SatoshiToElementsValue(uint64(wu["value"].(float64)))
				utxo := transaction.NewTxOutput(asset, value[:], script)
				updater.AddInWitnessUtxo(utxo, inIndex)
				redeemScript, _ := hex.DecodeString(in["redeemScript"].(string))
				updater.AddInRedeemScript(redeemScript, inIndex)
			}
			updater.AddInSighashType(txscript.SigHashType(int(in["sighashType"].(float64))), inIndex)
		}

		for outIndex, vOut := range v["outputs"].([]interface{}) {
			out := vOut.(map[string]interface{})
			redeemScript, _ := hex.DecodeString(out["redeemScript"].(string))
			updater.AddOutRedeemScript(redeemScript, outIndex)
		}

		base64Res, err := updater.Data.ToBase64()
		if err != nil {
			t.Fatal(err)
		}
		hexRes, err := updater.Data.ToHex()
		if err != nil {
			t.Fatal(err)
		}
		expectedBase64 := v["expectedBase64"].(string)
		expectedHex := v["expectedHex"].(string)
		if base64Res != expectedBase64 {
			t.Fatalf("Got: %s, expected: %s", base64Res, expectedBase64)
		}
		if hexRes != expectedHex {
			t.Fatalf("Got: %s, expected: %s", hexRes, expectedHex)
		}
	}
}

func TestUpdaterAddInput(t *testing.T) {
	inputs := make([]*transaction.TxInput, 0)
	outputs := make([]*transaction.TxOutput, 0)
	p, err := New(inputs, outputs, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	updater, err := NewUpdater(p)
	if err != nil {
		t.Fatal(err)
	}

	hash, err := hex.DecodeString(
		"000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f")
	if err != nil {
		t.Fatal(err)
	}

	txInput := transaction.TxInput{
		Hash:  hash,
		Index: 2,
	}

	assert.Equal(t, 0, len(updater.Data.UnsignedTx.Inputs))
	assert.Equal(t, 0, len(updater.Data.Inputs))

	updater.AddInput(&txInput)

	assert.Equal(t, 1, len(updater.Data.UnsignedTx.Inputs))
	assert.Equal(t, 1, len(updater.Data.Inputs))
}

func TestUpdaterAddOutput(t *testing.T) {
	inputs := make([]*transaction.TxInput, 0)
	outputs := make([]*transaction.TxOutput, 0)
	p, err := New(inputs, outputs, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	updater, err := NewUpdater(p)
	if err != nil {
		t.Fatal(err)
	}

	script, err := hex.DecodeString(
		"76a91439397080b51ef22c59bd7469afacffbeec0da12e88ac")
	if err != nil {
		t.Fatal(err)
	}

	asset, err := hex.DecodeString(
		"5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225")
	if err != nil {
		t.Fatal(err)
	}

	txOutput := transaction.TxOutput{
		Asset:  asset,
		Value:  []byte{byte(42)},
		Script: script,
	}

	assert.Equal(t, 0, len(updater.Data.UnsignedTx.Outputs))
	assert.Equal(t, 0, len(updater.Data.Outputs))

	updater.AddOutput(&txOutput)

	assert.Equal(t, 1, len(updater.Data.UnsignedTx.Outputs))
	assert.Equal(t, 1, len(updater.Data.Outputs))
}

func TestUpdaterAddReissuance(t *testing.T) {
	inputs := make([]*transaction.TxInput, 0)
	outputs := make([]*transaction.TxOutput, 0)
	p, err := New(inputs, outputs, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	updater, err := NewUpdater(p)
	if err != nil {
		t.Fatal(err)
	}

	inHash, _ := hex.DecodeString(
		"000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f",
	)

	lbtcInput := transaction.NewTxInput(
		bufferutil.ReverseBytes(inHash),
		2,
	)
	updater.AddInput(lbtcInput)

	inputBlinder, _ := hex.DecodeString("70d9f71278aa15ae9d6750cb29cc329f79a25f6678e14dbeb32913548c228ac9")
	tokenCommitment, _ := hex.DecodeString("0ac86a00e7d0fabac7aaee22d0709a071d0dc40da7cb76df3eda7e00b0bdd1224f")
	tokenScript, _ := hex.DecodeString("0014603e8a2c6346e01a6f0d5ecaec0b1da5a9fd3df1")
	tokenValue, _ := hex.DecodeString("089a992f8381397fb9df79fc3121612c85925a5b984baed66cab4903710300ef4c")
	tokenNonce, _ := hex.DecodeString("03f8590c3f339896cdb77a53d4bed6916faa67eb6c624fa124d39bf0d180726d44")
	// dummy proofs, they won't actually be used but they're required to be not
	// null, otherwise the output is not recognized as confidential
	tokenRangeProof, _ := hex.DecodeString("00")
	tokenSurjectionProof, _ := hex.DecodeString("00")

	utxo := &transaction.TxOutput{
		Asset:           tokenCommitment,
		Script:          tokenScript,
		Value:           tokenValue[:],
		Nonce:           tokenNonce,
		RangeProof:      tokenRangeProof,
		SurjectionProof: tokenSurjectionProof,
	}
	arg := AddReissuanceArg{
		InputHash:    "ca584d98e93fece72a7097f4cdefb2372837f2d085061ec87bf3c7d8ca7622cd",
		InputIndex:   1,
		InputBlinder: inputBlinder,
		Entropy:      "1acb83d51ebfe7454cb68718e2bf0665124dd05e525a95ab33b8403e7ff5f6f7",
		AssetAmount:  100,
		TokenAmount:  0.5,
		AssetAddress: "ert1qvqlg5trrgmsp5mcdtm9wczca5k5l6003jrwf5j",
		WitnessUtxo:  utxo,
		Network:      &network.Regtest,
	}
	err = updater.AddReissuance(arg)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, len(updater.Data.Inputs), 2)
	assert.Equal(t, len(updater.Data.Outputs), 2)
	reissuanceNonce :=
		updater.Data.UnsignedTx.Inputs[1].Issuance.AssetBlindingNonce
	assert.Equal(t, reissuanceNonce, inputBlinder)

	asset := hex.EncodeToString(
		bufferutil.ReverseBytes(updater.Data.UnsignedTx.Outputs[0].Asset[1:]),
	)
	token := hex.EncodeToString(
		bufferutil.ReverseBytes(updater.Data.UnsignedTx.Outputs[1].Asset[1:]),
	)
	expectedToken := "4307771267e443764fdad22b9893c1cbe413dcc736258ebb590a31035f3c143e"
	expectedAsset := "8e80d20a43ee55d5a26d2ac16ea5319c494a193dbb5d2ffc18c7e6b4525f2125"
	assert.Equal(t, expectedAsset, asset)
	assert.Equal(t, expectedToken, token)
}
