using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Exoft.Security.OAuthServer.Samples.Controllers
{
    [Route("api")]
    public class ResourceController : Controller
    {
        [Authorize(Roles = "Administrator"), HttpGet, Route("message")]
        public IActionResult GetMessage()
        {
            var identity = User.Identity as ClaimsIdentity;
            if (identity == null)
            {
                return BadRequest();
            }

            var result = new StringBuilder();

            foreach (var claim in identity.Claims)
            {
                result.AppendLine(Json(claim).Value.ToString());
                result.AppendLine();
            }

            return Content($"Identity's claims:\n{result}");
        }
    }
}