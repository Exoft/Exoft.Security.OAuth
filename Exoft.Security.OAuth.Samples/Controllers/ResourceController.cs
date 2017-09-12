using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using AspNet.Security.OAuth.Validation;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace Exoft.Security.OAuth.Samples.Controllers
{
    [Authorize(AuthenticationSchemes = OAuthValidationDefaults.AuthenticationScheme, Roles = "Administrator")]
    [Route("api")]
    public class ResourceController : Controller
    {
        [HttpGet, Route("message")]
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
