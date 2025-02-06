using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Threading.Tasks;
using System.Net.Http.NegotiateAuthentication;

class Program
{
    static async Task Main(string[] args)
    {
        string url = "https://mon-serveur.local/api"; // Remplace par ton URL
        string username = "monUser";
        string password = "monMotDePasse";
        string domain = "MONDOMAINE"; // Mettre null si pas de domaine

        try
        {
            // Créer le gestionnaire d’authentification
            var negotiateAuth = new NegotiateAuthenticationClient(new NegotiateAuthenticationClientOptions
            {
                Package = "NTLM", // Forcer l'utilisation de NTLM
                Credential = new NetworkCredential(username, password, domain),
                TargetName = url, // Cible du serveur
                RequiredProtectionLevel = ProtectionLevel.None, // Pas de chiffrement TLS au niveau applicatif
                MutualAuthentication = false
            });

            using var client = new HttpClient();
            var request = new HttpRequestMessage(HttpMethod.Get, url);

            // Premier échange : on envoie une requête sans authentification
            var response = await client.SendAsync(request);
            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                // Le serveur a répondu avec un challenge, on récupère le WWW-Authenticate
                if (response.Headers.WwwAuthenticate.Count > 0)
                {
                    string challenge = response.Headers.WwwAuthenticate.ToString();

                    // Générer la réponse NTLM
                    string authResponse = negotiateAuth.GetOutgoingBlob(challenge);

                    // Ajouter l'entête Authorization avec la réponse NTLM
                    request = new HttpRequestMessage(HttpMethod.Get, url);
                    request.Headers.Authorization = new AuthenticationHeaderValue("Negotiate", authResponse);

                    response = await client.SendAsync(request);
                }
            }

            // Vérification du succès
            if (response.IsSuccessStatusCode)
            {
                Console.WriteLine("Authentification réussie !");
                string content = await response.Content.ReadAsStringAsync();
                Console.WriteLine("Réponse : " + content);
            }
            else
            {
                Console.WriteLine($"Échec de l'authentification : {response.StatusCode}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Erreur : {ex.Message}");
        }
    }
}
