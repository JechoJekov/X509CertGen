using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;

namespace Common.Security.Cryptography.X509Certificates
{
    /// <summary>
    /// Represents an RSA key that is kept in memory only.
    /// </summary>
    /// <remarks>
    /// CAUTION The Dispose method must be called to make sure the key is not persisted on the machine.
    /// </remarks>
    public sealed class InMemoryRsaKey : IDisposable
    {
        public RSACryptoServiceProvider Key { get; private set; }

        public InMemoryRsaKey(int keySize)
        {
            // CAUTION "CspProviderFlags.CreateEphemeralKey" CANNOT be used since the key is not exportable.
            Key = new RSACryptoServiceProvider(keySize, new CspParameters() { Flags = CspProviderFlags.UseDefaultKeyContainer });
        }

        public void Dispose()
        {
            Key.PersistKeyInCsp = false;
        }
    }
}
