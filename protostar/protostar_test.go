package protostar

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tendermint/tendermint/config"
)

func TestAppendKeyWithValueIfNotEmpty(t *testing.T) {
	type funcInput struct {
		args []string
		arg  string
		val  string
	}
	testCases := []struct {
		name     string
		input    funcInput
		expected []string
	}{
		0: {
			name: "empty value",
			input: funcInput{
				args: []string{"--arg1", "val1"},
				arg:  "--arg2",
				val:  "",
			},
			expected: []string{"--arg1", "val1"},
		},
		1: {
			name: "non-empty value",
			input: funcInput{
				args: []string{"--arg1", "val1"},
				arg:  "--arg2",
				val:  "val2",
			},
			expected: []string{"--arg1", "val1", "--arg2", "val2"},
		},
	}
	for i, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			if got := appendKeyWithValueIfNotEmpty(tt.input.args, tt.input.arg, tt.input.val); !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("testCase%d failed: appendKeyWithValueIfNotEmpty() = %v, expected %v", i, got, tt.expected)
			}
		})
	}
}

func TestNetworkArgs(t *testing.T) {
	type funcInput struct {
		conf *config.ProtostarConfig
	}
	testCases := []struct {
		name     string
		input    funcInput
		expected []string
	}{
		0: {
			name: "empty config",
			input: funcInput{
				conf: &config.ProtostarConfig{},
			},
			expected: []string{},
		},
		1: {
			name: "non-empty config",
			input: funcInput{
				conf: &config.ProtostarConfig{
					AccountAddress: "accountAddress",
					ChainId:        "chainId",
					GatewayUrl:     "gatewayURL",
					Network:        "network",
					PrivateKeyPath: "privateKeyPath",
				},
			},
			expected: []string{
				"--account-address", "accountAddress",
				"--chain-id", "chainId",
				"--gateway-url", "gatewayURL",
				"--network", "network",
				"--private-key-path", "privateKeyPath",
			},
		},
	}
	for i, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			if got := networkArgs(tt.input.conf); !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("testCase%d failed: networkArgs() = %v, want %v", i, got, tt.expected)
			}
		})
	}
}

func TestExecuteCommand(t *testing.T) {
	type funcInput struct {
		pConf *config.ProtostarConfig
		args  []string
	}
	testCases := []struct {
		name     string
		input    funcInput
		expected []byte
		error    bool
		errorMsg string
	}{
		0: {
			name: "empty args",
			input: funcInput{
				pConf: &config.ProtostarConfig{},
				args:  []string{},
			},
			error:    true,
			errorMsg: "executeCommand: args must be non-empty",
		},
		1: {
			name: "echo command",
			input: funcInput{
				pConf: &config.ProtostarConfig{},
				args:  []string{"echo", "hello"},
			},
			expected: []byte("hello\n"),
		},
		2: {
			name: "echo command with network args",
			input: funcInput{
				pConf: &config.ProtostarConfig{
					AccountAddress: "accountAddress",
					ChainId:        "chainId",
					GatewayUrl:     "gatewayURL",
					Network:        "network",
					PrivateKeyPath: "privateKeyPath",
				},
				args: []string{"echo", "hello"},
			},
			expected: []byte("hello --account-address accountAddress --chain-id chainId --gateway-url gatewayURL --network network --private-key-path privateKeyPath\n"),
		},
		3: {
			name: "random not existing command",
			input: funcInput{
				pConf: &config.ProtostarConfig{},
				args:  []string{"random-not-existing-command"},
			},
			error: true,
		},
	}
	for i, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			got, err := executeCommand(tt.input.pConf, tt.input.args)
			if tt.error {
				if err == nil {
					t.Errorf("testCase%d failed: executeCommand() error = %v, wantErr %v", i, err, tt.error)
				}
				if tt.errorMsg != "" && err.Error() != tt.errorMsg {
					t.Errorf("testCase%d failed: executeCommand() error = %v, wantErr %v", i, err, tt.errorMsg)
				}
				return
			}
			if err != nil {
				t.Errorf("testCase%d failed: executeCommand() error = %v, wantErr %v", i, err, tt.error)
			}
			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("testCase%d failed: executeCommand() = %v, want %v", i, got, tt.expected)
			}
		})
	}
}

func TestGetClassHashHex(t *testing.T) {
	testCases := []struct {
		name     string
		input    []byte
		expected string
		error    error
	}{
		0: {
			name:     "empty input",
			input:    []byte(""),
			expected: "",
			error:    fmt.Errorf("could not find class hash hex in stdout: %s", ""),
		},
		1: {
			name:     "invalid one-line input",
			input:    []byte("invalid input"),
			expected: "",
			error:    fmt.Errorf("could not find class hash hex in stdout: %s", "invalid input"),
		},
		2: {
			name:     "valid one-line input",
			input:    []byte("Class hash: 0x1234567890"),
			expected: "0x1234567890",
			error:    nil,
		},
		3: {
			name:     "valid multi-line input",
			input:    []byte("Example first line,\nsecond line with some hash: 0x9876543210\nClass hash: 0x1234567890\nLast line with some hash: 0x9459459459"),
			expected: "0x1234567890",
			error:    nil,
		},
		4: {
			name:     "invalid multi-line input",
			input:    []byte("Example first line,\nsecond line with some hash: 0x9876543210\nhash: 0x1234567890\nLast line with some hash: 0x9459459459\nhash: 0x1234567890"),
			expected: "",
			error:    fmt.Errorf("could not find class hash hex in stdout: %s", "Example first line,\nsecond line with some hash: 0x9876543210\nhash: 0x1234567890\nLast line with some hash: 0x9459459459\nhash: 0x1234567890"),
		},
		5: {
			name:     "invalid input without 0x prefix",
			input:    []byte("Class hash: 1234567890"),
			expected: "",
			error:    fmt.Errorf("could not find class hash hex in stdout: %s", "Class hash: 1234567890"),
		},
		6: {
			name:     "invalid input with 0x prefix and invalid hash",
			input:    []byte("Class hash: 0x12345OPW78Z9CV"),
			expected: "",
			error:    fmt.Errorf("could not find class hash hex in stdout: %s", "Class hash: 0x12345OPW78Z9CV"),
		},
	}
	for i, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getClassHashHex(tt.input)
			if err != nil {
				if tt.error == nil || err.Error() != tt.error.Error() {
					t.Errorf("testCase%d failed: getClassHash() error = %v, wantErr %v", i, err, tt.error)
				}
				return
			}
			if got != tt.expected {
				t.Errorf("testCase%d failed: getClassHash() = %v, want %v", i, got, tt.expected)
			}
		})
	}
}

func TestGetTransactionHashHex(t *testing.T) {
	testCases := []struct {
		name     string
		input    []byte
		expected string
		error    error
	}{
		0: {
			name:  "empty input",
			input: []byte(""),
			error: fmt.Errorf("could not find transaction hash hex in stdout: %s", ""),
		},
		1: {
			name:  "invalid one-line input",
			input: []byte("invalid input"),
			error: fmt.Errorf("could not find transaction hash hex in stdout: %s", "invalid input"),
		},
		2: {
			name:     "valid one-line input",
			input:    []byte("Transaction hash: 0x1234567890"),
			expected: "0x1234567890",
		},
		3: {
			name:     "valid multi-line input",
			input:    []byte("Example first line,\nsecond line with some hash: 0x9876543210\nTransaction hash: 0x1234567890\nLast line with some hash: 0x9459459459"),
			expected: "0x1234567890",
		},
		4: {
			name:  "invalid multi-line input",
			input: []byte("Example first line,\nsecond line with some hash: 0x9876543210\nhash: 0x1234567890\nLast line with some hash: 0x9459459459\nhash: 0x1234567890"),
			error: fmt.Errorf("could not find transaction hash hex in stdout: %s", "Example first line,\nsecond line with some hash: 0x9876543210\nhash: 0x1234567890\nLast line with some hash: 0x9459459459\nhash: 0x1234567890"),
		},
		5: {
			name:  "invalid input without 0x prefix",
			input: []byte("Transaction hash: 1234567890"),
			error: fmt.Errorf("could not find transaction hash hex in stdout: %s", "Transaction hash: 1234567890"),
		},
		6: {
			name:  "invalid input with 0x prefix and invalid hash",
			input: []byte("Transaction hash: 0x12345OPW78Z9CV"),
			error: fmt.Errorf("could not find transaction hash hex in stdout: %s", "Transaction hash: 0x12345OPW78Z9CV"),
		},
	}
	for i, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getTransactionHashHex(tt.input)
			if err != nil {
				if tt.error == nil || err.Error() != tt.error.Error() {
					t.Errorf("testCase%d failed: getTransactionHash() error = %v, wantErr %v", i, err, tt.error)
				}
				return
			}
			if got != tt.expected {
				t.Errorf("testCase%d failed: getTransactionHash() = %v, want %v", i, got, tt.expected)
			}
		})
	}
}

func TestGetTransactionHashFelt(t *testing.T) {
	testCases := []struct {
		name     string
		input    []byte
		expected string
		error    error
	}{
		0: {
			name:  "empty input",
			input: []byte(""),
			error: fmt.Errorf("could not find transaction hash felt in stdout: %s", ""),
		},
		1: {
			name:  "invalid one-line input",
			input: []byte("invalid input"),
			error: fmt.Errorf("could not find transaction hash felt in stdout: %s", "invalid input"),
		},
		2: {
			name:     "valid one-line input",
			input:    []byte("Transaction hash: 1234567890"),
			expected: "1234567890",
		},
		3: {
			name:     "valid multi-line input",
			input:    []byte("Example first line,\nsecond line with some hash: 0x9876543210\nTransaction hash: 1234567890\nLast line with some hash: 9459459459"),
			expected: "1234567890",
		},
		4: {
			name:  "invalid multi-line input",
			input: []byte("Example first line,\nsecond line with some hash: 0x9876543210\nhash: 0x1234567890\nLast line with some hash: 0x9459459459\nhash: 0x1234567890"),
			error: fmt.Errorf("could not find transaction hash felt in stdout: %s", "Example first line,\nsecond line with some hash: 0x9876543210\nhash: 0x1234567890\nLast line with some hash: 0x9459459459\nhash: 0x1234567890"),
		},
		5: {
			name:  "invalid input with 0x prefix",
			input: []byte("Transaction hash: 0x1234567890"),
			error: fmt.Errorf("could not find transaction hash felt in stdout: %s", "Transaction hash: 0x1234567890"),
		},
		6: {
			name:  "invalid input without 0x prefix and invalid integer",
			input: []byte("Transaction hash: 12345OPW78Z9CV"),
			error: fmt.Errorf("could not find transaction hash felt in stdout: %s", "Transaction hash: 12345OPW78Z9CV"),
		},
	}
	for i, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getTransactionHashFelt(tt.input)
			if err != nil {
				if tt.error == nil || err.Error() != tt.error.Error() {
					t.Errorf("testCase%d failed: getTransactionHash() error = %v, wantErr %v", i, err, tt.error)
				}
				return
			}
			if got != tt.expected {
				t.Errorf("testCase%d failed: getTransactionHash() = %v, want %v", i, got, tt.expected)
			}
		})
	}
}

func TestGetContractAddress(t *testing.T) {
	testCases := []struct {
		name     string
		input    []byte
		expected string
		error    error
	}{
		0: {
			name:  "empty input",
			input: []byte(""),
			error: fmt.Errorf("could not find contract address hex in stdout: %s", ""),
		},
		1: {
			name:  "invalid one-line input",
			input: []byte("invalid input"),
			error: fmt.Errorf("could not find contract address hex in stdout: %s", "invalid input"),
		},
		2: {
			name:     "valid one-line input",
			input:    []byte("Contract address: 0x1234567890"),
			expected: "0x1234567890",
		},
		3: {
			name:     "valid multi-line input",
			input:    []byte("Example first line,\nsecond line with some hash: 0x9876543210\nContract address: 0x1234567890\nLast line with some hash: 0x9459459459"),
			expected: "0x1234567890",
		},
		4: {
			name:  "invalid multi-line input",
			input: []byte("Example first line,\nsecond line with some hash: 0x9876543210\nhash: 0x1234567890\nLast line with some hash: 0x9459459459\nhash: 0x1234567890"),
			error: fmt.Errorf("could not find contract address hex in stdout: %s", "Example first line,\nsecond line with some hash: 0x9876543210\nhash: 0x1234567890\nLast line with some hash: 0x9459459459\nhash: 0x1234567890"),
		},
		5: {
			name:  "invalid input without 0x prefix",
			input: []byte("Contract address: 1234567890"),
			error: fmt.Errorf("could not find contract address hex in stdout: %s", "Contract address: 1234567890"),
		},
		6: {
			name:  "invalid input with 0x prefix and invalid hash",
			input: []byte("Contract address: 0x12345OPW78Z9CV"),
			error: fmt.Errorf("could not find contract address hex in stdout: %s", "Contract address: 0x12345OPW78Z9CV"),
		},
	}
	for i, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getContractAddressHex(tt.input)
			if err != nil {
				if tt.error == nil || err.Error() != tt.error.Error() {
					t.Errorf("testCase%d failed: getContractAddress() error = %v, wantErr %v", i, err, tt.error)
				}
				return
			}
			if got != tt.expected {
				t.Errorf("testCase%d failed: getContractAddress() = %v, want %v", i, got, tt.expected)
			}
		})
	}
}

// Before running protostar tests make sure that
// * protostar is installed
// * starknet-devnet is running  on http://127.0.0.1:5050 with seed 42
func TestDeclare(t *testing.T) {
	// Checking whether protostar is installed
	cmd := exec.Command("command", "-v", "protostar")
	if err := cmd.Run(); err != nil {
		t.Skip("protostar is not installed")
	}

	// Checking whether starknet-devnet is running on port 5050
	_, err := http.Get("http://127.0.0.1:5050/is_alive")
	if err != nil {
		t.Skip("starknet-devnet is not running")
	}

	// Creating temporary file with private key
	tmpFile, err := os.CreateTemp(".", "seed_42_private_key")
	if err != nil {
		t.Fatal(fmt.Errorf("could not create temporary file for private key: %w", err))
	}
	tmpFile.Write([]byte("0xbdd640fb06671ad11c80317fa3b1799d"))
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	// Setting up the protostar config
	conf := config.DefaultProtostarConfig()
	conf.PrivateKeyPath = tmpFile.Name()
	conf.AccountAddress = "0x347be35996a21f6bf0623e75dbce52baba918ad5ae8d83b6f416045ab22961a"

	// Testing the Declare function
	classHashHex, transactionHashHex, err := Declare(conf, "../cairo/build/main.json")
	require.NoError(t, err)
	require.NotEmpty(t, classHashHex)
	require.NotEmpty(t, transactionHashHex)
}

// Before running protostar tests make sure that
// * protostar is installed
// * starknet-devnet is running  on http://127.0.0.1:5050 with seed 42
func TestDeploy(t *testing.T) {
	// Checking whether protostar is installed
	cmd := exec.Command("command", "-v", "protostar")
	if err := cmd.Run(); err != nil {
		t.Skip("protostar is not installed")
	}

	// Checking whether starknet-devnet is running on port 5050
	_, err := http.Get("http://127.0.0.1:5050/is_alive")
	if err != nil {
		t.Skip("starknet-devnet is not running")
	}

	// Creating temporary file with private key
	tmpFile, err := os.CreateTemp(".", "seed_42_private_key")
	if err != nil {
		t.Fatal(fmt.Errorf("could not create temporary file for private key: %w", err))
	}
	tmpFile.Write([]byte("0xbdd640fb06671ad11c80317fa3b1799d"))
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	// Setting up the protostar config
	conf := config.DefaultProtostarConfig()
	conf.PrivateKeyPath = tmpFile.Name()
	conf.AccountAddress = "0x347be35996a21f6bf0623e75dbce52baba918ad5ae8d83b6f416045ab22961a"

	// Calling the Declare to get the class hash for the Deploy function
	ch, th, err := Declare(conf, "../cairo/build/main.json")
	require.NoError(t, err)
	require.NotEmpty(t, ch)
	require.NotEmpty(t, th)

	// Testing the Deploy function
	contractAddressHex, transactionHashHex, err := Deploy(conf, ch)
	require.NoError(t, err)
	require.NotEmpty(t, contractAddressHex)
	require.NotEmpty(t, transactionHashHex)
}

// ################################ Skipped ################################
// There is a bug in Protostar's Invoke command, it is not working properly
// until it is fixed, we will skip this test.
// see https://github.com/software-mansion/protostar/issues/1220
// #########################################################################
//
// // Before running protostar tests make sure that
// // * protostar is installed
// // * starknet-devnet is running  on http://127.0.0.1:5050 with seed 42
// func TestInvoke(t *testing.T) {
// 	// Checking whether protostar is installed
// 	cmd := exec.Command("command", "-v", "protostar")
// 	if err := cmd.Run(); err != nil {
// 		t.Skip("protostar is not installed")
// 	}

// 	// Checking whether starknet-devnet is running on port 5050
// 	_, err := http.Get("http://127.0.0.1:5050/is_alive")
// 	if err != nil {
// 		t.Skip("starknet-devnet is not running")
// 	}

// 	// Creating temporary file with private key
// 	tmpFile, err := os.CreateTemp(".", "seed_42_private_key")
// 	if err != nil {
// 		t.Fatal(fmt.Errorf("could not create temporary file for private key: %w", err))
// 	}
// 	tmpFile.Write([]byte("0xbdd640fb06671ad11c80317fa3b1799d"))
// 	tmpFile.Close()
// 	defer os.Remove(tmpFile.Name())

// 	// Setting up the protostar config
// 	conf := config.DefaultProtostarConfig()
// 	conf.PrivateKeyPath = tmpFile.Name()
// 	conf.AccountAddress = "0x347be35996a21f6bf0623e75dbce52baba918ad5ae8d83b6f416045ab22961a"

// 	// Calling the Declare function
// 	chh, thh, err := Declare(conf, "../cairo/build/main.json")
// 	require.NoError(t, err)
// 	require.NotEmpty(t, chh)
// 	require.NotEmpty(t, thh)

// 	// Calling the Deploy function
// 	contractAddressHex, thf, err := Deploy(conf, chh)
// 	require.NoError(t, err)
// 	require.NotEmpty(t, contractAddressHex)
// 	require.NotEmpty(t, thf)

// 	invokeInputs := []string{}

// 	// Testing the Invoke function
// 	transactionHashHex, err := Invoke(conf, contractAddressHex, invokeInputs)
// 	require.NoError(t, err)
// 	require.NotEmpty(t, transactionHashHex)
// }