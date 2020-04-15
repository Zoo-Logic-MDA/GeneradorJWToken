using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Text;
using System.Security.Claims;

using System.Security.Cryptography;
using JWT.Builder;
using JWT.Algorithms;
using System.Collections.Generic;
using JWT.Serializers;
using JWT;
using System.IO;

namespace getJWT
{
    //https://github.com/jwt-dotnet/jwt
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("¡DIFERENCIA MINUSCULA DE MAYUSCULA!\n");
            Console.WriteLine("IdCliente:");
            string idCliente = Console.ReadLine();
            Console.WriteLine("Clave Privada:");
            string clavePrivada = Console.ReadLine();
            Console.WriteLine("Usuario DF:");
            string usuarioDF = Console.ReadLine();
            Console.WriteLine("Clave DF:");
            string claveDF = Console.ReadLine();

            var timeStamp = ((DateTime.Now.AddYears(2)).ToUniversalTime().Ticks - 621355968000000000) / 10000000;

            var token = new JwtBuilder()
               .WithAlgorithm(new HMACSHA256Algorithm())
               .WithSecret(clavePrivada)
               .AddClaim("exp", timeStamp)
               .AddClaim("usuario", usuarioDF)
               .AddClaim("password", getHMAC256(claveDF,clavePrivada))
               .Build();

            Console.WriteLine("\nJWToken (expiración 2 años):");
            Console.WriteLine(token);
            Console.ReadKey();
            
        }
        
        static string getHMAC256(string claveDF,string clavePrivada)
        {
            byte[] newKey = Encoding.ASCII.GetBytes(clavePrivada);
            HMACSHA256 hmacsha256 = new HMACSHA256(newKey);
            byte[] byteArray = Encoding.ASCII.GetBytes(claveDF);
            MemoryStream stream = new MemoryStream(byteArray);
            string result = hmacsha256.ComputeHash(stream).Aggregate("", (s, e) => s + String.Format("{0:x2}", e), s => s);
            return result;
        }

    }
}
