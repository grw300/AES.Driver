using System;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;

using System.Text.RegularExpressions;
using System.Collections;

namespace AES.Driver
{
	class MainClass
	{
		private static CbcBlockCipher cipher;
		private static KeyParameter keyParameter;
		private static byte[] encryptedText;
		private static byte[] decryptedText;

		public static void Main(string[] args)
		{
			var p = Hex.Decode("8000 7000 6000 5000 4000 3000 2000 1000");
			var k = Hex.Decode("0000 0000 0000 0000 0000 0000 0000 0001");


			MainClass.cipher = new CbcBlockCipher(new AesEngine());
			MainClass.keyParameter = new KeyParameter(k);

			EncryptDecrypt(p, k);

			Console.WriteLine(Regex.Replace(Hex.ToHexString(p), ".{4}", "$0 "));
			Console.WriteLine(Regex.Replace(Hex.ToHexString(k), ".{4}", "$0 "));

			Console.WriteLine(Regex.Replace(Hex.ToHexString(encryptedText), ".{4}", "$0 "));
			Console.WriteLine(Regex.Replace(Hex.ToHexString(decryptedText), ".{4}", "$0 "));

		}

		public static void EncryptDecrypt(byte[] p, byte[] k)
		{
			cipher.Init(true, keyParameter);
			encryptedText = new byte[p.Length];
			cipher.ProcessBlock(p, 0, encryptedText, 0);

			cipher.Init(false, keyParameter);
			decryptedText = new byte[encryptedText.Length];
			cipher.ProcessBlock(encryptedText, 0, decryptedText, 0);
		}
	}
}
