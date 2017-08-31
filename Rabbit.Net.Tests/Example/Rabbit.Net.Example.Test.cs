using System;
using Rabbit.Net;
using System.Security.Cryptography;
using System.Linq;

namespace Rabbit.Net.Rabbit.Net.Tests.Example
{
    sealed class RabbitTESTDONOTUSE
    {
        public RabbitTESTDONOTUSE() {}
        private void MainTest()
        {
            RabbitCipher rc = new RabbitCipher(); //initialize
            //generate IV And Key to be Used
            rc.GenerateIV();
            rc.GenerateKey();
            //----------------------------<<

            //begin encrypting
            try
            {
                using (SymmetricAlgorithm RabbitCipher = new RabbitCipher())
                using (ICryptoTransform transform = RabbitCipher.CreateEncryptor(rc.Key, rc.IV))
                {
                    byte[] test_file = new byte[7675]; //not an actual file
                    byte[] output = new byte[test_file.Length]; //encyption does not change file size
                    if (test_file.Length % 16 != 0) //encrypts in bytes of 16 so if it is not perfectly made of 16 blocks we will need to transform the final block
                    {
                        int encrypted_bytes = transform.TransformBlock(test_file, 0, test_file.Length, output, 0);
                        //now the data is all encrypted in the output byte[] array
                    }
                    else
                    {
                        int encrypted_bytes = transform.TransformBlock(test_file, 0, test_file.Length, output, 0);
                        //now the data is all encrypted in the output byte[] array
                    }
                }
            }
            catch(Exception ex)
            {
                Console.WriteLine("\nThere was An Error When Encrypting <> Error Code:\n\n" + ex.ToString());
            }
            //------------------<<

            //begin Decrypting
            try
            {
                using (SymmetricAlgorithm RabbitCipher = new RabbitCipher())
                using (ICryptoTransform transform = RabbitCipher.CreateDecryptor(rc.Key, rc.IV))
                {
                    byte[] encrypted_data = new byte[4343];
                    byte[] plaintext_data = new byte[encrypted_data.Length];
                    if(encrypted_data.Length % 16 != 0)
                    {
                        int decrypted_bytes = transform.TransformBlock(encrypted_data, 0, encrypted_data.Length, plaintext_data, 0);
                        //now decrypted
                    }
                    else
                    {
                        transform.TransformBlock(encrypted_data, 0, encrypted_data.Length, plaintext_data, 0);
                        //now decrypted
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("\nThere was An Error When Decrypting <> Error Code:\n\n" + ex.ToString());
            }
            //------------------<<
        }
    }
}
