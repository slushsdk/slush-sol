package consensus

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tendermint/tendermint/types"
)

func TestFormatSignedHeader(t *testing.T) {
	lightBlockString := `{"signed_header":{"header":{"version":{"block":"11","app":"1"},"chain_id":"test-chain-IrF74Y","height":"2","time":"2022-10-14T11:06:35.413940948Z","last_block_id":{"hash":"01F491396B02D56397E056A39D7EF263DF45254F89C40B17B28CFB6FB7CCFD2E","parts":{"total":1,"hash":"0740C1781E703EF4BE74626BB920F569D5CE37200C2DC91226D0D0099E52AC09"}},"last_commit_hash":"02E02E5672C11EC3A039ECFA9943FA2BB343A4A152BFFDA19DAA10F37B7541CD","data_hash":"049EE3EBA8C1600700EE1B87EB599F16716B0B1022947733551FDE4050CA6804","validators_hash":"052C9B411FF6CF27281D4528BE392356B299E1BB94E78ED9F64936DB602E9AE3","next_validators_hash":"052C9B411FF6CF27281D4528BE392356B299E1BB94E78ED9F64936DB602E9AE3","consensus_hash":"04B6EE42C4CB17A4129A2B6135C8FB4B6CBA7A5F9A18B87C4EFEFB74F2F0F24E","app_hash":"0000000000000000000000000000000000000000000000000000000000000000","last_results_hash":"049EE3EBA8C1600700EE1B87EB599F16716B0B1022947733551FDE4050CA6804","evidence_hash":"049EE3EBA8C1600700EE1B87EB599F16716B0B1022947733551FDE4050CA6804","proposer_address":"07505C4FCAD35561F9118A049D9C97CB01C2F60D845BDBE25639BB1706EA0275"},"commit":{"height":"2","round":0,"block_id":{"hash":"01F94F4D5BCFBE0DDAB054594502152C52360597273194CEE5ADB579311EC87B","parts":{"total":1,"hash":"03B603B1874C195AE40D080CAEB3104142A0FCD9BE3E7A8FFC405353E408889E"}},"signatures":[{"block_id_flag":2,"validator_address":"07505C4FCAD35561F9118A049D9C97CB01C2F60D845BDBE25639BB1706EA0275","timestamp":"2022-10-14T11:06:40.929141572Z","signature":"BCKoIfq1Fxpa/I2De9PhoN592+Bj3zVSKHMiUTD6mEAFbWctuH8wILbzsT4l4SGVsI4VxbGWL1fT/1Oek/qZCA=="}]}},"canonical":true}`
	expected := `{"header":{"consensus_data":{"block":11,"app":1},"height":2,"time":{"nanos":1665745595413940948},"last_block_id":{"hash":884425833596017687902070213747808739115022713891866619587347960517452692782,"part_set_header":{"total":1,"hash":3280603427672755996697561151661387289552035726080851369010608355561641782281}},"last_commit_hash":1300719250649302888673721710201729934164570534884866772308748105278349984205,"data_hash":2089986280348253421170679821480865132823066470938446095505822317253594081284,"validators_hash":2340377040213079208513181851626792215421593955873165280879009333623007386339,"next_validators_hash":2340377040213079208513181851626792215421593955873165280879009333623007386339,"consensus_hash":2132461975834504200398180281070409533541683498016798668455504133351250391630,"app_hash":0,"last_results_hash":2089986280348253421170679821480865132823066470938446095505822317253594081284,"evidence_hash":2089986280348253421170679821480865132823066470938446095505822317253594081284,"proposer_address":3308174817124847388915938526006361282230966751698668845121616562821790302837},"commit":{"height":2,"round":0,"block_id":{"hash":892805091259252719451078399408285323788861340980283502742818584651789944955,"part_set_header":{"total":1,"hash":1678530202937530276285116262009511904790607301550138088769956212479453857950}}}}`

	var lightBlock types.LightBlock
	json.Unmarshal([]byte(lightBlockString), &lightBlock)

	res := FormatSignedHeader(*lightBlock.SignedHeader)

	resLightBlock, _ := json.Marshal(res)
	resLightBlockString := string(resLightBlock)

	assert.Equal(t, expected, resLightBlockString)
}

func TestFormatValidatorSet(t *testing.T) {
	validatorsString := `{"block_height":"3","validators":[{"address":"07505C4FCAD35561F9118A049D9C97CB01C2F60D845BDBE25639BB1706EA0275","pub_key":{"type":"tendermint/PubKeyStark","value":"BCSyZuiwaiVNC0tMTPQrXGoZQpYImwdyV3K88ltKu7EC2JFryijF/Td9JaXiEVWqpwsSwllhhrY8lJDBmwt2BA=="},"voting_power":"10","proposer_priority":"0"}],"count":"1","total":"1"}`
	expected := `{"proposer":{"Address":3308174817124847388915938526006361282230966751698668845121616562821790302837,"pub_key":{"ecdsa":1874089173934400596279690104790724610118670100261327038271526874663074053041},"voting_power":10,"proposer_priority":0},"total_voting_power":10}`

	var validators types.ValidatorSet
	json.Unmarshal([]byte(validatorsString), &validators)

	validators.Proposer = validators.Validators[0]

	res := FormatValidatorSet(&validators)

	resLightBlock, _ := json.Marshal(res)
	resLightBlockString := string(resLightBlock)

	assert.Equal(t, expected, resLightBlockString)
}

func TestFormatValidator(t *testing.T) {
	trustedLightBlockString := `{"signed_header":{"header":{"version":{"block":"11","app":"1"},"chain_id":"test-chain-IrF74Y","height":"2","time":"2022-10-14T13:24:31.520445159Z","last_block_id":{"hash":"05C32CDC85F91A5985E8B677F4E66BF9E2E6AD81C3EF78631A3C261FF66B0CBF","parts":{"total":1,"hash":"06A26A085152107697F0ECFE8A03E98DD359F7704CF4180A8372DE9D97A2FFC1"}},"last_commit_hash":"04454198E80175870CDA3A3C01E19188A485AC6D5D786D58865577BE3737F34A","data_hash":"049EE3EBA8C1600700EE1B87EB599F16716B0B1022947733551FDE4050CA6804","validators_hash":"06424BDF5299B41922D5FC97DE1D4EE3C4072D2EB0D4904F8F44452E978C3B6A","next_validators_hash":"06424BDF5299B41922D5FC97DE1D4EE3C4072D2EB0D4904F8F44452E978C3B6A","consensus_hash":"04B6EE42C4CB17A4129A2B6135C8FB4B6CBA7A5F9A18B87C4EFEFB74F2F0F24E","app_hash":"0000000000000000000000000000000000000000000000000000000000000000","last_results_hash":"049EE3EBA8C1600700EE1B87EB599F16716B0B1022947733551FDE4050CA6804","evidence_hash":"049EE3EBA8C1600700EE1B87EB599F16716B0B1022947733551FDE4050CA6804","proposer_address":"00BDFC2A72D8828A45531126520BF5F981434D95922DC2867857874FA9966B0E"},"commit":{"height":"2","round":0,"block_id":{"hash":"048DC96483670246BECAF0EDACCC3E9E8A56EDEFC3E2BE2D5CB74897BAEAC67C","parts":{"total":1,"hash":"02E4528C17BF48E6612B6A7FBB2EE554EDF5F3DB00CFD124369BC20E19716327"}},"signatures":[{"block_id_flag":2,"validator_address":"00BDFC2A72D8828A45531126520BF5F981434D95922DC2867857874FA9966B0E","timestamp":"2022-10-14T13:24:37.127453388Z","signature":"BA4U7G4bat7vjxHWZVtZNTOUIl88gAqP4Xzw9LzSRzwD26wQed88+841SxS3IDA7NX+JECv1QuE0p6aABVUhog=="}]}},"canonical":false}`
	untrustedLightBlockString := `{"signed_header":{"header":{"version":{"block":"11","app":"1"},"chain_id":"test-chain-IrF74Y","height":"3","time":"2022-10-14T13:24:44.50752585Z","last_block_id":{"hash":"048DC96483670246BECAF0EDACCC3E9E8A56EDEFC3E2BE2D5CB74897BAEAC67C","parts":{"total":1,"hash":"02E4528C17BF48E6612B6A7FBB2EE554EDF5F3DB00CFD124369BC20E19716327"}},"last_commit_hash":"0107550A529CAAD7A9438FB11E5528602B63BC83418713DD2B09FA7E30C626DD","data_hash":"049EE3EBA8C1600700EE1B87EB599F16716B0B1022947733551FDE4050CA6804","validators_hash":"06424BDF5299B41922D5FC97DE1D4EE3C4072D2EB0D4904F8F44452E978C3B6A","next_validators_hash":"06424BDF5299B41922D5FC97DE1D4EE3C4072D2EB0D4904F8F44452E978C3B6A","consensus_hash":"04B6EE42C4CB17A4129A2B6135C8FB4B6CBA7A5F9A18B87C4EFEFB74F2F0F24E","app_hash":"0000000000000000000000000000000000000000000000000000000000000000","last_results_hash":"049EE3EBA8C1600700EE1B87EB599F16716B0B1022947733551FDE4050CA6804","evidence_hash":"049EE3EBA8C1600700EE1B87EB599F16716B0B1022947733551FDE4050CA6804","proposer_address":"00BDFC2A72D8828A45531126520BF5F981434D95922DC2867857874FA9966B0E"},"commit":{"height":"3","round":0,"block_id":{"hash":"01159AAF5196DB2F20D9E99A4367EE93465226AF348162652061E19E32803F1B","parts":{"total":1,"hash":"03B70ED423A9D39E956967F49CE3228FDEEB4F6982383FED18BCD2DB755E5B34"}},"signatures":[{"block_id_flag":2,"validator_address":"00BDFC2A72D8828A45531126520BF5F981434D95922DC2867857874FA9966B0E","timestamp":"2022-10-14T13:24:49.554053779Z","signature":"B/ikqqI3zPMbl5bzJFzQ8s1l7dEwW7DJ9w97gL70Qs4G7WzxArvNYItwQ3Gy5XnDT4/zh3tEWfWbFq8JV50mDQ=="}]}},"canonical":false}`
	validatorSetString := `{"block_height":"3","validators":[{"address":"00BDFC2A72D8828A45531126520BF5F981434D95922DC2867857874FA9966B0E","pub_key":{"type":"tendermint/PubKeyStark","value":"B19CsyMnLUkCfXu4joziTCOhJexv/O5tIwBLXV5Rs9kGAbRLvgQAW3Id24QbxGGxcOWxDEba43ykDQGgv2+wBQ=="},"voting_power":"10","proposer_priority":"0"}],"count":"1","total":"1"}`
	expected := `{"chain_id_array":[116,7310314358442582377,7939082473277174873],"trusted_commit_sig_array":[{"block_id_flag":{"BlockIDFlag":2},"validator_address":335674479734934146889037038263903380498452542860978104900782795296756624142,"timestamp":{"nanos":1665753877127453388},"signature":{"signature_r":1834131662309943167060654729634590738983734585222746799362362058903754262332,"signature_s":1745065597501682152537867859965459308365142243262023073853228716084356784546}}],"untrusted_commit_sig_array":[{"block_id_flag":{"BlockIDFlag":2},"validator_address":335674479734934146889037038263903380498452542860978104900782795296756624142,"timestamp":{"nanos":1665753889554053779},"signature":{"signature_r":3605504498823257379762570133327870210455706278164450482388963404778814325454,"signature_s":3133371732092557530256163168714261110099475276750495027673839161202089731597}}],"validator_array":[{"Address":335674479734934146889037038263903380498452542860978104900782795296756624142,"pub_key":{"ecdsa":3334500756028199475433036722527134417926233723147766471089429384364098171865},"voting_power":10,"proposer_priority":0}],"trusted":{"header":{"consensus_data":{"block":11,"app":1},"height":2,"time":{"nanos":1665753871520445159},"last_block_id":{"hash":2606409042684652237028761825612341298588373841266340846590208831812555967679,"part_set_header":{"total":1,"hash":3000838125350084652609540693524514269948277526780094801048010237669338709953}},"last_commit_hash":1931616577660260768497627594988710925560949687119466413940080031015097594698,"data_hash":2089986280348253421170679821480865132823066470938446095505822317253594081284,"validators_hash":2831012649517925635638083284349758092553206116379646415063645608642406529898,"next_validators_hash":2831012649517925635638083284349758092553206116379646415063645608642406529898,"consensus_hash":2132461975834504200398180281070409533541683498016798668455504133351250391630,"app_hash":0,"last_results_hash":2089986280348253421170679821480865132823066470938446095505822317253594081284,"evidence_hash":2089986280348253421170679821480865132823066470938446095505822317253594081284,"proposer_address":335674479734934146889037038263903380498452542860978104900782795296756624142},"commit":{"height":2,"round":0,"block_id":{"hash":2059766791315474971233242291515003944317013849850428055013818287621749261948,"part_set_header":{"total":1,"hash":1308036548029847327855861229891709942163426033933946107172305588954015556391}}}},"untrusted":{"header":{"consensus_data":{"block":11,"app":1},"height":3,"time":{"nanos":1665753884507525850},"last_block_id":{"hash":2059766791315474971233242291515003944317013849850428055013818287621749261948,"part_set_header":{"total":1,"hash":1308036548029847327855861229891709942163426033933946107172305588954015556391}},"last_commit_hash":465267704775716075860689654059997816995530962997902813659991924419196233437,"data_hash":2089986280348253421170679821480865132823066470938446095505822317253594081284,"validators_hash":2831012649517925635638083284349758092553206116379646415063645608642406529898,"next_validators_hash":2831012649517925635638083284349758092553206116379646415063645608642406529898,"consensus_hash":2132461975834504200398180281070409533541683498016798668455504133351250391630,"app_hash":0,"last_results_hash":2089986280348253421170679821480865132823066470938446095505822317253594081284,"evidence_hash":2089986280348253421170679821480865132823066470938446095505822317253594081284,"proposer_address":335674479734934146889037038263903380498452542860978104900782795296756624142},"commit":{"height":3,"round":0,"block_id":{"hash":490484232464039218793463646794795012959740951355156173400258415888395419419,"part_set_header":{"total":1,"hash":1680373902317584836581677072736116216148431538470704822243182371928708897588}}}},"validator_set_args":{"proposer":{"Address":335674479734934146889037038263903380498452542860978104900782795296756624142,"pub_key":{"ecdsa":3334500756028199475433036722527134417926233723147766471089429384364098171865},"voting_power":10,"proposer_priority":0},"total_voting_power":10},"verification_args":{"current_time":{"nanos":1665753884507526850},"max_clock_drift":{"nanos":10},"trusting_period":{"nanos":99999999999999999999}}}`

	var validatorSet types.ValidatorSet
	json.Unmarshal([]byte(validatorSetString), &validatorSet)
	validatorSet.Proposer = validatorSet.Validators[0]

	var trustedLightBlock, untrustedLightBlock types.LightBlock
	json.Unmarshal([]byte(trustedLightBlockString), &trustedLightBlock)
	json.Unmarshal([]byte(untrustedLightBlockString), &untrustedLightBlock)

	trustingPeriod, _ := big.NewInt(0).SetString("99999999999999999999", 10)

	res := FormatCallData(trustedLightBlock, untrustedLightBlock, &validatorSet, big.NewInt(1665753884507526850), big.NewInt(10), trustingPeriod)

	resExternal, _ := json.Marshal(res)
	resExternalString := string(resExternal)

	assert.Equal(t, expected, resExternalString)
}