using SLD.Tezos.Cryptography;
using SLD.Tezos.Cryptography.BIP39;
using SLD.Tezos.Cryptography.NaCl;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;

namespace NornWallet
{
    public static class Program
    {
        static byte[] publicKey;
        static byte[] privateKey;
        static string edsk;
        static string tz1;
        static string mnemonic;
        static string hash;
        static string counter;

        static void Main(string[] args)
        {
            Console.WriteLine("----==== Norn Wallet ====----");
            Console.WriteLine();
            Console.WriteLine("Norn Wallet created by Norn Community: https://t.me/invest_flood");
            Console.WriteLine();
            Console.WriteLine("Choose action:");
            Console.WriteLine("1 - Import mnemonic");
            Console.WriteLine("2 - Import private key");
            Console.WriteLine("Esc - exit");
            var key = Console.ReadKey().Key;
            Console.WriteLine();
            switch (key)
            {
                case ConsoleKey.D1:
                    ImportSeed();
                    break;
                case ConsoleKey.D2:
                    ImportSk();
                    break;
                default:
                    return;
            }
            Console.WriteLine();
            Console.Write("Enter current block hash: ");
            hash = Console.ReadLine();
            Console.Write("Enter account counter: ");
            counter = Console.ReadLine();
            int cnt = int.Parse(counter);
            Console.Write("Enter destination address: ");
            string to = Console.ReadLine();
            Console.Write("Enter amount: ");
            string amount = Console.ReadLine();
            Console.Write("Enter fee: ");
            string fee = Console.ReadLine();

            var hashBytesString = CryptoServices.DecodePrefixed(HashType.Block, hash).ToHexString();
            var toBytesString = CryptoServices.DecodePrefixed(HashType.PublicKeyHash, to).ToHexString();

            Console.WriteLine();
            cnt++;
            string transferOp = hashBytesString + "080000" + CryptoServices.DecodePrefixed(HashType.PublicKeyHash, tz1).ToHexString() + int.Parse(fee).EncodeInt32() + cnt.EncodeInt32() + 400.EncodeInt32() + 0.EncodeInt32() +
                ((int)(decimal.Parse(amount, CultureInfo.InvariantCulture) * 1000000)).EncodeInt32() + "01" + toBytesString + "0000";
            var opBytes = ("03" + transferOp).HexToByteArray();
            var hashedData = CryptoServices.Hash(opBytes, 32);
            var bsign = CryptoServices.CreateSignature(privateKey, hashedData);
            var inject = transferOp + bsign.ToHexString();
            Console.WriteLine("Operation hex:");
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine(inject);
            Console.ForegroundColor = ConsoleColor.Gray;
        }

        private static void ImportSeed()
        {
            Console.ForegroundColor = ConsoleColor.DarkGreen;
            Console.WriteLine("Import mnemonic");
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.Write("Enter words: ");
            mnemonic = Console.ReadLine();
            Console.Write("Enter password or press Enter: ");
            string pass = Console.ReadLine();
            var bip = new BIP39(mnemonic, pass);
            var seed = new ArraySegment<byte>(bip.SeedBytes, 0, Ed25519.PrivateKeySeedSizeInBytes);
            Ed25519.KeyPairFromSeed(out publicKey, out privateKey, seed.ToArray());
            tz1 = CryptoServices.CreatePrefixedHash(HashType.PublicKeyHash, publicKey);
            edsk = CryptoServices.EncodePrefixed(HashType.Private, privateKey);
        }

        private static void ImportSk()
        {
            Console.ForegroundColor = ConsoleColor.DarkGreen;
            Console.WriteLine("Import private key");
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.Write("Enter encoded private key: ");
            edsk = Console.ReadLine();
            var keys = CryptoServices.ImportEd25519(edsk);
            publicKey = keys.Item1;
            privateKey = keys.Item2;
            tz1 = CryptoServices.CreatePrefixedHash(HashType.PublicKeyHash, publicKey);
            edsk = CryptoServices.EncodePrefixed(HashType.Private, privateKey);
        }

        public static string ToHexString(this byte[] data)
        {
            var hex = new StringBuilder(data.Length * 2);
            foreach (byte b in data)
                hex.AppendFormat("{0:x2}", b);

            return hex.ToString();
        }

        public static string EncodeInt32(this int value)
        {
            List<byte> bytes = new List<byte>();

            bool first = true;
            while (first || value > 0)
            {
                first = false;
                byte lower7bits = (byte)(value & 0x7f);
                value >>= 7;
                if (value > 0)
                    lower7bits |= 128;
                bytes.Add(lower7bits);
            }
            return bytes.ToArray().ToHexString();
        }

        public static byte[] HexToByteArray(this string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }
    }
}
