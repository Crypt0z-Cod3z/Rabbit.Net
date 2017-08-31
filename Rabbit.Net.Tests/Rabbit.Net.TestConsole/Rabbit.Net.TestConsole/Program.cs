/*
 * Created by SharpDevelop.
 * User: Brian_2
 * Date: 8/30/2017
 * Time: 8:38 PM
 * 
 * To change this template use Tools | Options | Coding | Edit Standard Headers.
 */
 
 /*
  * These ARE FOR TESTS DO NOT USE IN YOUR CODE****
  */
 
using System;
using System.Text;
using Rabbit.Net;

namespace Rabbit.Net.TestConsole
{
	class Program
	{
		public static void Main(string[] args)
		{
			RabbitCipher rc = new RabbitCipher();
			//test all accessible features>>
			Console.WriteLine(rc.BitsEncryptedPerIteration.ToString());
			Console.WriteLine("\n\n" + rc.BlockSize.ToString());
			Console.WriteLine("\n\n" + rc.IVBitSize.ToString());
			Console.WriteLine("\n\n" + rc.LegalBlockSizes.ToString());
			Console.WriteLine("\n\n" + rc.LegalKeySizes.ToString());
			Console.WriteLine("\n\n" + rc.KeySize.ToString());
			//test exception catchers
			rc.IV = Encoding.ASCII.GetBytes("TESTFOR"); //should throw an error;
			rc.Key = Encoding.ASCII.GetBytes("ERRORRIGHTHERE"); //should throw an error
			rc.CheckIV(rc.IV);
			rc.CheckKey(rc.Key);
			Console.Write("\n\nPress any key to continue . . . ");
			Console.ReadKey(true);
		}
	}
}