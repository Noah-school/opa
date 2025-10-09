using OpenPolicyAgent.Opa.AspNetCore;
using System.Text;

namespace API.Helpers
{
    public class PostBodyContextDataProvider : IContextDataProvider
    {
        public object GetContextData(HttpContext context)
        {
            var contextData = new Dictionary<string, object>();
            
            try
            {
                context.Request.EnableBuffering();
                context.Request.Body.Position = 0;
                
                var bodyContent = ReadRequestBodyAsync(context.Request.Body).GetAwaiter().GetResult();
                
                context.Request.Body.Position = 0;
                
                contextData["requestBody"] = bodyContent;
            }
            catch (Exception ex)
            {
                contextData["requestBodyError"] = ex.Message;
            }
            
            return contextData;
        }
        
        private static async Task<string> ReadRequestBodyAsync(Stream body)
        {
            using var reader = new StreamReader(body, Encoding.UTF8, leaveOpen: true);
            return await reader.ReadToEndAsync();
        }
    }
}