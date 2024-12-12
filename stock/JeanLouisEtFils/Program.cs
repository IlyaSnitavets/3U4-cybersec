// See https://aka.ms/new-console-template for more information
using Encryption.Blowfish;
using System.Security.Cryptography;

var superdupersecret = "a3bd614b27864e3f854b971f9df1a802";


String encrypter(String source) {
    byte[] buf = System.Text.UTF8Encoding.UTF8.GetBytes(source); ; // data you want to encrypt
    buf = buf.CopyAndPadIfNotAlreadyPadded();
    var iv = RandomNumberGenerator.GetBytes(8);
    var cbc = new BlowfishCtr(superdupersecret);
    Console.WriteLine(BitConverter.ToString(buf));
    var ok = cbc.CryptOrDecrypt(buf, iv);
    Console.WriteLine(BitConverter.ToString(buf));
    String encrypted = System.Text.UTF8Encoding.UTF8.GetString(buf);
    Console.WriteLine(encrypted);
    
    
    ok = cbc.CryptOrDecrypt(buf, iv);
    Console.WriteLine(BitConverter.ToString(buf));
    String decrypted = System.Text.UTF8Encoding.UTF8.GetString(buf);
    Console.WriteLine(decrypted);

    return encrypted;

}



Console.WriteLine("Hello, World!");

var key = "a3bd614b27864e3f854b971f9df1a802"; // cipher key
var iv = RandomNumberGenerator.GetBytes(8); // IV
byte[] buf = System.Text.UTF8Encoding.UTF8.GetBytes("super duper password 1!"); ; // data you want to encrypt
//buf = buf.CopyAndPadIfNotAlreadyPadded();

var cbc = new BlowfishCtr(key);
Console.WriteLine(BitConverter.ToString(buf));
var ok = cbc.CryptOrDecrypt(buf, iv);
Console.WriteLine(BitConverter.ToString(buf));
ok = cbc.CryptOrDecrypt(buf, iv);
Console.WriteLine(BitConverter.ToString(buf));
encrypter("joris");
encrypter("Vincent Carrier est un prof qui sait comment manier les $$$$$$");


