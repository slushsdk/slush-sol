package smartcontracts

import (
	"encoding/json"
	"io/fs"
	"math/big"
	"os"
	"os/exec"

	"github.com/tendermint/tendermint/internal/consensus"
	"github.com/tendermint/tendermint/types"
)

func Invoke(vd types.VerifierDetails, id consensus.InvokeData, currentTime *big.Int) ([]byte, error) {

	trustingPeriod, _ := big.NewInt(0).SetString("99999999999999999999", 10)

	cd := consensus.FormatCallData(id.TrustedLightB, id.UntrustedLightB, id.TrustedLightB.ValidatorSet, currentTime, big.NewInt(10), trustingPeriod)
	ext := consensus.External{VerifierAddress: vd.VerifierAddress, CallData: cd}
	jsonString, _ := json.Marshal(ext)

	err := os.WriteFile("/invoke_input.json", jsonString, fs.FileMode(0644))

	if err != nil {
		return []byte{}, err
	}

	// devnet is different
	var cmd *exec.Cmd
	if vd.NetworkDetails.Network == "devnet" {
		cmd = exec.Command("protostar", "migrate", "migrations/migration_02.cairo", "--gateway-url", "http://127.0.0.1:5050/", "--chain-id", "1536727068981429685321", "--private-key-path", vd.AccountPrivKeyPath, "--account-address", vd.AccountAddress.Text(16), "--no-confirm")
		cmd.Dir = "./cairo"
	} else {
		cmd = exec.Command("protostar", "migrate", "migrations/migration_02.cairo", "--network", vd.NetworkDetails.Network, "--private-key-path", vd.AccountPrivKeyPath, "--account-address", vd.AccountAddress.Text(16), "--no-confirm")
		cmd.Dir = "./cairo"
	}

	stdout, err := cmd.CombinedOutput()

	return stdout, err
}