# z.Security

Implement AES, LZ and Sodium (NaCL) Encryption

Sample Sodium Implementation

```c#
  var alice = Encryption.GenerateKeyPair();
  var bob = Encryption.GenerateKeyPair();

  var message = "Hello Bob!! are you the builder?";

  var encMessage = Encryption.SendMessage(message, alice.PrivateKey, bob.PublicKey);

  var rcms = Encryption.ReadMessage(encMessage, bob.PrivateKey, alice.PublicKey);

  Assert.AreEqual(message, rcms);
```
