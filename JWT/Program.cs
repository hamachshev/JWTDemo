using System.Reflection.Metadata;
using System.Security.Cryptography;

namespace JWT;
using System;
using System.Text;
// https://jwt.io/introduction
class Program
{
    static void Main(string[] args)
    {
        string header = """
                        {
                          "alg": "RS256",
                          "typ": "JWT"
                        }
                        """;
        header.Trim('\n');
        string headerBase64 = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(header));
        Console.WriteLine("Enter payload, for example:");
        Console.WriteLine("{");
        Console.WriteLine("\"sub\": \"1234567890\",");
        Console.WriteLine(" \"name\": \"John Doe\",");
        Console.WriteLine(" \"admin\": true");
        Console.WriteLine(" }");
        Console.WriteLine("and then type END <enter>");
        string line;
        string multiLineInput = "";
        while ((line = Console.ReadLine()) != "END")
        {
            multiLineInput += line + "\n";
        }

        // string formattedJson = @$"{multiLineInput}".Trim('\n');
        string formattedJson = multiLineInput.Trim('\n');
        byte [] payload = Encoding.UTF8.GetBytes(formattedJson);
        string payloadbase64 = Base64UrlEncoder.Encode(payload);
        
        Console.WriteLine(sign(headerBase64, payloadbase64));
        
        
        

      
    }

    private static string sign(string headerBase64, string payloadbase64)
    {
        string concat = headerBase64 +"."+ payloadbase64;
        byte[] bytes = System.Text.Encoding.UTF8.GetBytes(concat);
        byte [] hash = SHA256.Create().ComputeHash(bytes);
        byte[] publicKey;
        byte[] signed;
        using (var publicPrivate = new RSACryptoServiceProvider(2048))
        {
            string publicKeyPem = ExportPublicKeyToPem(publicPrivate);
            string privateKeyPem = ExportPrivateKeyToPem(publicPrivate);
            // Print the results
            Console.WriteLine("Public Key:");
            Console.WriteLine(publicKeyPem);

            Console.WriteLine("\nPrivate Key:");
            Console.WriteLine(privateKeyPem);
            signed = publicPrivate.SignHash(hash, CryptoConfig.MapNameToOID("SHA256"));
        }

        string final = concat + "." + Base64UrlEncoder.Encode(signed);
        


        return final;
    }
    
    static string ExportPublicKeyToPem(RSA rsa)
    {
        // Export public key in X.509 SubjectPublicKeyInfo (PEM format)
        byte[] publicKeyBytes = rsa.ExportSubjectPublicKeyInfo();
        return ConvertToPem(publicKeyBytes, "PUBLIC KEY");
    }

    static string ExportPrivateKeyToPem(RSA rsa)
    {
        // Export private key in PKCS#8 (PEM format)
        byte[] privateKeyBytes = rsa.ExportPkcs8PrivateKey();
        return ConvertToPem(privateKeyBytes, "PRIVATE KEY");
    }

    static string ConvertToPem(byte[] keyBytes, string keyType)
    {
        // Convert byte array to Base64 PEM string
        StringBuilder sb = new StringBuilder();
        sb.AppendLine($"-----BEGIN {keyType}-----");
        sb.AppendLine(Convert.ToBase64String(keyBytes, Base64FormattingOptions.InsertLineBreaks));
        sb.AppendLine($"-----END {keyType}-----");
        return sb.ToString();
    }
}




 public static class Base64UrlEncoder
 {
     // Method to encode a byte array to Base64Url
     public static string Encode(byte[] input)
     {
         // Standard Base64 encode
         string base64 = Convert.ToBase64String(input);

         // Convert Base64 to Base64Url
         base64 = base64
             .Replace('+', '-') // Replace '+' with '-'
             .Replace('/', '_') // Replace '/' with '_'
             .TrimEnd('=');     // Remove padding '='

         return base64;
     }

     // Method to decode a Base64Url string back to a byte array
     public static byte[] Decode(string input)
     {
         // Add padding to make the length a multiple of 4
         string base64 = input
             .Replace('-', '+') // Replace '-' with '+'
             .Replace('_', '/') // Replace '_' with '/'
             .PadRight(input.Length + (4 - input.Length % 4) % 4, '=');

         return Convert.FromBase64String(base64);
     }
 }


        


 