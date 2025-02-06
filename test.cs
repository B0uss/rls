using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Text;
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
            // Création de l'objet d'authentification NTLM
            var negotiateAuth = new NegotiateAuthentication(new NegotiateAuthenticationClientOptions
            {
                Package = "NTLM", // Force NTLM
                Credential = new NetworkCredential(username, password, domain),
                TargetName = url, // Nom de la cible
                RequiredProtectionLevel = ProtectionLevel.None,
                MutualAuthentication = false
            });

            using var client = new HttpClient();

            // Étape 1: Envoyer une requête avec un blob NTLM vide (premier échange)
            byte[] outputBlob = negotiateAuth.GetOutgoingBlob(null, out NegotiateAuthenticationStatusCode statusCode);
            if (statusCode == NegotiateAuthenticationStatusCode.Unsupported)
            {
                throw new Exception("🚫 NTLM n'est pas supporté !");
            }

            Console.WriteLine("🔄 Envoi de la première requête NTLM...");
            var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.Authorization = new AuthenticationHeaderValue("NTLM", Convert.ToBase64String(outputBlob));

            var response = await client.SendAsync(request);

            // Étape 2: Vérifier si un challenge NTLM est renvoyé
            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                Console.WriteLine("🔄 Le serveur a répondu avec un challenge NTLM...");

                // Extraire le challenge NTLM depuis WWW-Authenticate
                string ntlmChallenge = null;
                foreach (var header in response.Headers.WwwAuthenticate)
                {
                    if (header.Scheme.Equals("NTLM", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrEmpty(header.Parameter))
                    {
                        ntlmChallenge = header.Parameter; // Récupérer le challenge
                        break;
                    }
                }

                if (string.IsNullOrEmpty(ntlmChallenge))
                {
                    throw new Exception("⚠️ Impossible de récupérer le challenge NTLM !");
                }

                Console.WriteLine($"🔑 Challenge NTLM reçu : {ntlmChallenge}");

                // Étape 3: Générer la réponse NTLM
                byte[] inputBlob = Convert.FromBase64String(ntlmChallenge);
                outputBlob = negotiateAuth.GetOutgoingBlob(inputBlob, out statusCode);

                if (statusCode == NegotiateAuthenticationStatusCode.Unsupported)
                {
                    throw new Exception("🚫 Erreur : NTLM n'est pas supporté !");
                }

                Console.WriteLine("✅ Génération de la réponse NTLM réussie !");

                // Étape 4: Renvoyer la requête avec l'authentification NTLM
                request = new HttpRequestMessage(HttpMethod.Get, url);
                request.Headers.Authorization = new AuthenticationHeaderValue("NTLM", Convert.ToBase64String(outputBlob));

                response = await client.SendAsync(request);
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
