using NUnit.Framework;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace z.Security.Test
{
    public class EncryptionTest
    {
        [SetUp]
        public void Setup()
        {
        }

        [TestCaseSource(nameof(HundredLoop))]
        public void TestSendAndRecieveMessage(int i)
        {

            var alice = Encryption.GenerateKeyPair();
            var bob = Encryption.GenerateKeyPair();

            var message = "Hello Bob!! are you the builder";

            var encMessage = Encryption.SendMessage(message, alice.PrivateKey, bob.PublicKey);
             
            var rcms = Encryption.ReadMessage(encMessage, bob.PrivateKey, alice.PublicKey);

            Assert.AreEqual(message, rcms);
        }

        private static readonly IEnumerable<int> HundredLoop = Enumerable.Range(0, 100);

        [Test]
        public void TestSendAndFail()
        {

            var alice = Encryption.GenerateKeyPair();
            var bob = Encryption.GenerateKeyPair();

            var message = "Hello Bob!! are you the builder";

            var encMessage = Encryption.SendMessage(message, alice.PrivateKey, bob.PublicKey);
             
            Assert.Throws<CryptographicException>(() =>
            {
                Encryption.ReadMessage(encMessage, alice.PrivateKey, bob.PublicKey);
            });
        }
    }
}