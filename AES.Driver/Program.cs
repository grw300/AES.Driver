using System;
using System.Diagnostics;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities.Encoders;

namespace AES.Driver
{
	class MainClass
	{
		private static CbcBlockCipher cipher;
		private static KeyParameter keyParameter;
		private static byte[] key;
		private static byte[] plainText;
		private static byte[] encryptedText;
		private static byte[] decryptedText;
		private static long aesMemory;

		public static void Main(string[] args)
		{
			
			key = Hex.Decode("0000 0000 0000 0000 0000 0000 0000 0001");

			plainText = Hex.Decode("8000 7000 6000 5000 4000 3000 2000 1000");

			aesMemory = GC.GetTotalMemory(false);
			MainClass.cipher = new CbcBlockCipher(new AesEngine());
			MainClass.keyParameter = new KeyParameter(key);

			EncryptDecrypt();

			Console.WriteLine($"Key:            {Regex.Replace(Hex.ToHexString(key), ".{4}", "$0 ")}");
			Console.WriteLine($"Plain Text:     {Regex.Replace(Hex.ToHexString(plainText), ".{4}", "$0 ")}");

			Console.WriteLine($"Encrypted Text: {Regex.Replace(Hex.ToHexString(encryptedText), ".{4}", "$0 ")}");
			Console.WriteLine($"Decrypted Text: {Regex.Replace(Hex.ToHexString(decryptedText), ".{4}", "$0 ")}");

			Console.WriteLine($"Approximate memory used by AES: {aesMemory} bytes");

			Stopwatch stopWatch = Stopwatch.StartNew();

			for (int i = 0; i < 3000000; i++)
			{
				Encrypt();
			}

			stopWatch.Stop();

			TimeSpan ts = stopWatch.Elapsed;

			Console.WriteLine($"Total seconds to encrypt 3 million times: {ts.TotalSeconds}");

			stopWatch.Reset();
			stopWatch.Start();

			for (int i = 0; i < 3000000; i++)
			{
				Decrypt();
			}

			stopWatch.Stop();

			ts = stopWatch.Elapsed;

			Console.WriteLine($"Total seconds to decrypt 3 million times: {ts.TotalSeconds}");
		}

		public static void EncryptDecrypt()
		{
			Encrypt();
			Decrypt();
			aesMemory = Math.Abs(aesMemory - GC.GetTotalMemory(false));
		}

		public static void Encrypt()
		{
			cipher.Init(true, keyParameter);
			encryptedText = new byte[plainText.Length];
			cipher.ProcessBlock(plainText, 0, encryptedText, 0);
		}

		public static void Decrypt()
		{
			cipher.Init(false, keyParameter);
			decryptedText = new byte[encryptedText.Length];
			cipher.ProcessBlock(encryptedText, 0, decryptedText, 0);
		}
	}
}
