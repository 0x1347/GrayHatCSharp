using System;
using System.IO;
using System.Net;


namespace FuzzingXS
{

    public class Fuzzing
    {
        public static void Main(string[] args)
        {
            if(args.Length == 0)
            {
                Console.WriteLine("Usage ./FuzzingGETRequests.exe <URL with ? and & chars>");
                return;
            }
            string url = args[0];
            // Get the index Of ? char in the link
            int index = url.IndexOf("?");
            // Store the parameter afer ? and & to use in Fuzzig
            string[] parms = url.Remove(0, index+1).Split('&');
            // foreach (string parm in parms)
            //     Console.WriteLine(parm);
            foreach (string parm in parms)
            {
                try {
                        
                    string xssUrl = url.Replace(parm, parm + "fd<xss>sa");
                    string sqlUrl = url.Replace(parm, parm + "fd'sa");
                    // Console.WriteLine(xssUrl);
                    // Console.WriteLine(sqlUrl);
                    HttpWebRequest request = (HttpWebRequest)WebRequest.Create(sqlUrl);
                    request.Method = "GET";
                    string sqlresp = string.Empty;
                    using (StreamReader rdr = new StreamReader(request.GetResponse().GetResponseStream()))
                    sqlresp = rdr.ReadToEnd();
                    request = (HttpWebRequest)WebRequest.Create(xssUrl);
                    request.Method = "GET";
                    string xssresp = string.Empty;
                    using (StreamReader rdr = new StreamReader(request.GetResponse().GetResponseStream()))
                    xssresp = rdr.ReadToEnd();
                    if (xssresp.Contains("<xss>"))
                        Console.WriteLine("Possible XSS point found in parameter: " + parm);
                    if (sqlresp.Contains("error in your SQL syntax"))
                        Console.WriteLine("SQL injection point found in parameter: " + parm);
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.ToString());
                }
            }
        }
    }
        
}
