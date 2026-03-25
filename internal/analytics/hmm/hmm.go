package hmm

// NumHiddenStates is the number of hidden states in the HMM.
const NumHiddenStates = 3

// HiddenState represents a state in the Hidden Markov Model.
type HiddenState int

const (
	HStateSecure   HiddenState = 0
	HStateInsecure HiddenState = 1
	HStateNeutral  HiddenState = 2
)

// String returns a human-readable name for the hidden state.
func (s HiddenState) String() string {
	switch s {
	case HStateSecure:
		return "Secure"
	case HStateInsecure:
		return "Insecure"
	case HStateNeutral:
		return "Neutral"
	default:
		return "Unknown"
	}
}

// NumAPICallTypes is the total number of observable API call types.
const NumAPICallTypes = 22

// API call type constants representing observable emissions.
const (
	APICallRSAGenerateKey   = 0
	APICallRSAEncrypt       = 1
	APICallRSADecrypt       = 2
	APICallRSASign          = 3
	APICallECDSAGenerateKey = 4
	APICallECDSASign        = 5
	APICallECDSAVerify      = 6
	APICallECDHGenerateKey  = 7
	APICallECDHSharedKey    = 8
	APICallAESNewCipher     = 9
	APICallAESGCM           = 10
	APICallAESCBC           = 11
	APICallAESCFB           = 12
	APICallAESCTR           = 13
	APICallSHA256           = 14
	APICallSHA512           = 15
	APICallSHA3             = 16
	APICallHMAC             = 17
	APICallMLKEMEncapsulate = 18
	APICallMLDSASign        = 19
	APICallMLDSAVerify      = 20
	APICallOther            = 21
)

// APICallName maps an API call constant to its string name.
var APICallName = map[int]string{
	APICallRSAGenerateKey:   "RSAGenerateKey",
	APICallRSAEncrypt:       "RSAEncrypt",
	APICallRSADecrypt:       "RSADecrypt",
	APICallRSASign:          "RSASign",
	APICallECDSAGenerateKey: "ECDSAGenerateKey",
	APICallECDSASign:        "ECDSASign",
	APICallECDSAVerify:      "ECDSAVerify",
	APICallECDHGenerateKey:  "ECDHGenerateKey",
	APICallECDHSharedKey:    "ECDHSharedKey",
	APICallAESNewCipher:     "AESNewCipher",
	APICallAESGCM:           "AESGCM",
	APICallAESCBC:           "AESCBC",
	APICallAESCFB:           "AESCFB",
	APICallAESCTR:           "AESCTR",
	APICallSHA256:           "SHA256",
	APICallSHA512:           "SHA512",
	APICallSHA3:             "SHA3",
	APICallHMAC:             "HMAC",
	APICallMLKEMEncapsulate: "MLKEMEncapsulate",
	APICallMLDSASign:        "MLDSASign",
	APICallMLDSAVerify:      "MLDSAVerify",
	APICallOther:            "Other",
}

// HMMParams holds the parameters of a 3-state, 22-observation HMM.
type HMMParams struct {
	// Initial state probabilities: π[i] = P(state_0 = i)
	Initial [NumHiddenStates]float64

	// Transition probabilities: A[i][j] = P(state_t+1 = j | state_t = i)
	Transition [NumHiddenStates][NumHiddenStates]float64

	// Emission probabilities: B[i][k] = P(obs_t = k | state_t = i)
	Emission [NumHiddenStates][NumAPICallTypes]float64
}
