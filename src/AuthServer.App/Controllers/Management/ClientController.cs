using AuthServer.App.Models;
using AuthServer.App.Services;
using Microsoft.AspNetCore.Mvc;

namespace AuthServer.App.Controllers.Management
{
    [ApiController]
    [Route("~/mgmt/[controller]")]
    public class ClientController : Controller
    {
        private readonly IOpenIddictApplicationService _applicationService;

        public ClientController(IOpenIddictApplicationService applicationService)
        {
            _applicationService = applicationService;
        }
        
        [HttpPost]
        public async Task Create(AuthServerClientRequest request)
        {
            await _applicationService.Create(request);
        }
    }
}