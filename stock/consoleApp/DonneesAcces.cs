using System;
using System.Collections.Generic;
using System.IO;
using Microsoft.Data.Sqlite;

//https://sqlitebrowser.org/   https://download.sqlitebrowser.org/DB.Browser.for.SQLite-3.12.2-win64.zip

// https://sqlitebrowser.org/ pour regarder dans le dedans de la BD
// https://www.codeguru.com/dotnet/using-sqlite-in-a-c-application/
namespace consoleApp
{
    class DonneesAcces
    {
        static SqliteConnection sqlite_conn = InitialiserConnexion();

        private static SqliteConnection InitialiserConnexion()
        {
            SqliteConnection sqlite_conn;
            try
            {
                sqlite_conn = new SqliteConnection("Data Source=sqlite.cem.ca;Default Timeout=5;");
                sqlite_conn.Open();
                throw new Exception();
            }
            catch (Exception)
            {
                // create the folder ".\data\data\data"
                var path = Path.Combine("..", "data", "data");
                System.IO.Directory.CreateDirectory(path);
                var databasePath = Path.Combine(path, "cyber.db");
                sqlite_conn = new SqliteConnection("Data Source="+databasePath+";");
                sqlite_conn.Open();
            }
            return sqlite_conn;
        }

        public static void BDCreerTables()
        {
            sqlite_conn.Open();
            SqliteCommand sqlite_cmd;
            string Createsql = "CREATE TABLE IF NOT EXISTS MUtilisateur" +
                               " (nom VARCHAR(200)," +
                               " motDePasse VARCHAR(200)," +
                               " nas VARCHAR(10))";

            sqlite_cmd = sqlite_conn.CreateCommand();
            sqlite_cmd.CommandText = Createsql;
            // create a second table MAnneeRevenu with the user name, the year and the income
            string Createsql1 = "CREATE TABLE IF NOT EXISTS MAnneeRevenu" +
                                " (nom VARCHAR(200)," +
                                " annee INT," +
                                " revenu INT)";
            var sqlite_cmd2 = sqlite_conn.CreateCommand();
            sqlite_cmd2.CommandText = Createsql1;
            try
            {
                sqlite_cmd.ExecuteNonQuery();
                sqlite_cmd2.ExecuteNonQuery();
            }
            catch (Exception e)
            {
                Console.Error.WriteLine(e.Data);
            }
            finally
            {
                sqlite_conn.Close();
            }
        }

        public static void BDCreerUtilisateur(Formulaires.FormulaireNouveauCompte compte)
        {
            sqlite_conn.Open();
            SqliteCommand sqlite_cmd = sqlite_conn.CreateCommand();
            sqlite_cmd.CommandText = "INSERT INTO MUtilisateur (nom, motDePasse, nas) VALUES (@nom, @motDePasse, @nas)";
            sqlite_cmd.Parameters.AddWithValue("@nom", compte.Nom);
            sqlite_cmd.Parameters.AddWithValue("@motDePasse", DonneesSecurite.HashThePassword(compte.MotDePasse));
            sqlite_cmd.Parameters.AddWithValue("@nas", DonneesSecurite.Encrypt(compte.NAS));
            sqlite_cmd.ExecuteNonQuery();
            sqlite_conn.Close();
        }
        
        public static List<DonneesUtilisateur> BDLireUtilisateurs()
        {
            sqlite_conn.Open();
            SqliteDataReader sqlite_datareader;
            SqliteCommand sqlite_cmd;
            sqlite_cmd = sqlite_conn.CreateCommand();
            List<DonneesUtilisateur> liste = new List<DonneesUtilisateur>();
            sqlite_cmd.CommandText = "SELECT * FROM MUtilisateur";

            sqlite_datareader = sqlite_cmd.ExecuteReader();
            while (sqlite_datareader.Read())
            {
                //string myreader = sqlite_datareader.GetString(0);
                DonneesUtilisateur compte = new DonneesUtilisateur();
                compte.Nom = sqlite_datareader.GetString(0);
                compte.MotDePasseHash = sqlite_datareader.GetString(1);
                compte.NAS = sqlite_datareader.GetString(2);
                //Console.WriteLine(DataSec.Decrypt(compte.NAS));
                liste.Add(compte);

                //Console.WriteLine(sqlite_datareader.GetString(0));
                //Console.WriteLine(sqlite_datareader.GetString(1));
                //Console.WriteLine(sqlite_datareader.GetString(2));
            }

            sqlite_conn.Close();
            return liste;
            //conn.Close();
        }

        public static List<DonneesAnneeRevenu> BDRevenusPour(string utilisateurConnecte)
        {
            sqlite_conn.Open();
            SqliteDataReader sqlite_datareader;
            SqliteCommand sqlite_cmd;
            sqlite_cmd = sqlite_conn.CreateCommand();
            List<DonneesAnneeRevenu> liste = new List<DonneesAnneeRevenu>();
            // execute the request and extract the data
            sqlite_cmd.CommandText = "SELECT * FROM MAnneeRevenu WHERE nom = '" + utilisateurConnecte + "'";
            sqlite_datareader = sqlite_cmd.ExecuteReader();
            while (sqlite_datareader.Read())
            {
                DonneesAnneeRevenu revenu = new DonneesAnneeRevenu();
                revenu.Nom = sqlite_datareader.GetString(0);
                revenu.Annee = sqlite_datareader.GetInt32(1);
                revenu.Revenu = sqlite_datareader.GetInt32(2);
                liste.Add(revenu);
            }
            return liste;
        }

        public static DonneesUtilisateur BDUtilisateurParSonNom(string nom)
        {
            sqlite_conn.Open();
            SqliteDataReader sqlite_datareader;
            SqliteCommand sqlite_cmd;
            sqlite_cmd = sqlite_conn.CreateCommand();
            sqlite_cmd.CommandText = "SELECT * FROM MUtilisateur WHERE nom = '" + nom + "'";

            sqlite_datareader = sqlite_cmd.ExecuteReader();
            DonneesUtilisateur compte = new DonneesUtilisateur();
            // get the user from the database
            while (sqlite_datareader.Read())
            {
                compte.Nom = sqlite_datareader.GetString(0);
                compte.MotDePasseHash = sqlite_datareader.GetString(1);
                compte.NAS = sqlite_datareader.GetString(2);
            }

            sqlite_conn.Close();
            return compte;
        }

        public static void BDEffacerTout()
        {
            // delete all the users
            sqlite_conn.Open();
            SqliteCommand sqlite_cmd;
            sqlite_cmd = sqlite_conn.CreateCommand();
            sqlite_cmd.CommandText = "DELETE FROM MUtilisateur";
            sqlite_cmd.ExecuteNonQuery();
            // make a second command to erase the other table
            sqlite_cmd.CommandText = "DELETE FROM MAnneeRevenu";
            sqlite_cmd.ExecuteNonQuery();
            sqlite_conn.Close();

        }

        public static void BDCreerRevenu(string utilisateurConnecte, int annee, int revenu)
        {
            sqlite_conn.Open();
            SqliteCommand sqlite_cmd = sqlite_conn.CreateCommand();

            // Check if the entry for the specified user and year already exists
            sqlite_cmd.CommandText = "SELECT COUNT(*) FROM MAnneeRevenu WHERE nom = @nom AND annee = @annee";
            sqlite_cmd.Parameters.AddWithValue("@nom", utilisateurConnecte);
            sqlite_cmd.Parameters.AddWithValue("@annee", annee);
            int count = Convert.ToInt32(sqlite_cmd.ExecuteScalar());

            if (count > 0)
            {
                // Update the existing entry
                sqlite_cmd.CommandText = "UPDATE MAnneeRevenu SET revenu = @revenu WHERE nom = @nom AND annee = @annee";
            }
            else
            {
                // Insert a new entry
                sqlite_cmd.CommandText = "INSERT INTO MAnneeRevenu (nom, annee, revenu) VALUES(@nom, @annee, @revenu)";
            }

            sqlite_cmd.Parameters.AddWithValue("@revenu", revenu);
            sqlite_cmd.ExecuteNonQuery();
            sqlite_conn.Close();
        }
    }
}