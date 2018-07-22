We need to be able serialize the state of things. This way we can bind effectively with other libraries, and comminicate over the network.

Types to serialize:
* BlindRequester
* BlindSigner
* Voter
* VoterSignature

The sub types in here:
* `ecdsa.PrivateKey`
* `ecdsa.PublicKey`
* `big.Int`
* the "`sessions`" variable of BlindSigner which is `map[ecdsa.PublicKey]big.Int`

Start with `big.Int` then do `ecdsa.PublicKey`, then either `map[ecdsa.PublicKey]big.Int` or `ecdsa.PrivateKey`.

Write tests as we go, basically taking one of these typees, marshalling it, then unmarshalling it, and comparing it with the original.

`big.Int` done now I need to do `ecds.PublicKey` this has a `elliptic.Curve` in it.

The serialized `elliptic.Curve` is a constant thing, it just contains the curve parameters.

Now for sessions
