using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Threading.Tasks;

class Program
{
    static async Task Main(string[] args)
    {
        string url = "https://mon-serveur.local/api"; // Remplace par ton URL cible
        string username = "monUser";
        string password = "monMotDePasse";
        string domain = "MONDOMAINE"; // Mettre null si pas de domaine

        try
        {
            // Création de l'authentification NTLM via NegotiateAuthentication
            var negotiateAuth = new NegotiateAuthentication(new NegotiateAuthenticationClientOptions
            {
                Package = "NTLM", // Forcer NTLM
                Credential = new NetworkCredential(username, password, domain),
                TargetName = url, // Cible du serveur
                RequiredProtectionLevel = ProtectionLevel.None, // Pas de chiffrement applicatif
                MutualAuthentication = false
            });

            using var client = new HttpClient();
            var request = new HttpRequestMessage(HttpMethod.Get, url);

            // Envoyer une première requête sans authentification pour obtenir le challenge
            var response = await client.SendAsync(request);
            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                // Récupérer le challenge NTLM du serveur
                string challenge = response.Headers.WwwAuthenticate.ToString();
                if (!string.IsNullOrEmpty(challenge))
                {
                    // Générer la réponse NTLM basée sur le challenge
                    byte[]? inputBlob = Convert.FromBase64String(challenge.Split(' ')[1]); // Extraire la partie utile du challenge
                    byte[] outputBlob = negotiateAuth.GetOutgoingBlob(inputBlob, out NegotiateAuthenticationStatusCode statusCode);

                    if (statusCode == NegotiateAuthenticationStatusCode.Completed || statusCode == NegotiateAuthenticationStatusCode.ContinueNeeded)
                    {
                        // Ajouter l'entête Authorization avec la réponse NTLM
                        request = new HttpRequestMessage(HttpMethod.Get, url);
                        request.Headers.Authorization = new AuthenticationHeaderValue("Negotiate", Convert.ToBase64String(outputBlob));

                        response = await client.SendAsync(request);
                    }
                }
            }

            // Vérifier si la connexion est réussie
            if (response.IsSuccessStatusCode)
            {
                Console.WriteLine("✅ Authentification réussie !");
                string content = await response.Content.ReadAsStringAsync();
                Console.WriteLine("Réponse : " + content);
            }
            else
            {
                Console.WriteLine($"❌ Échec de l'authentification : {response.StatusCode}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"⚠️ Erreur : {ex.Message}");
        }
    }
}
