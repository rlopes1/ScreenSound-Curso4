using Microsoft.AspNetCore.Components.Authorization;
using ScreenSound.Web.Response;
using System.Net.Http.Json;
using System.Security.Claims;

namespace ScreenSound.Web.Services;

public class AuthAPI(IHttpClientFactory factory) : AuthenticationStateProvider
{

    private bool autenticado = false; // Variável para controlar se o usuário está autenticado ou não

    private readonly HttpClient _httpClient = factory.CreateClient("API");

    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {

        autenticado = false; // Reseta o estado de autenticação

        // Inicializa ClaimsPrincipal como não autenticado

        var pessoa = new ClaimsPrincipal(); // não autenticado

        var response = await _httpClient.GetAsync("auth/manage/info");

        if (response.IsSuccessStatusCode)
        {

            var info = await response.Content.ReadFromJsonAsync<InfoPessoaResponse>();

            Claim[] dados =
                [
                    new Claim(ClaimTypes.Name, info.Email),
                    new Claim(ClaimTypes.Email, info.Email)
                ];

            var identity = new ClaimsIdentity(dados, "Cookies");

            pessoa = new ClaimsPrincipal(identity); // autenticado

            autenticado = true; // Define que o usuário está autenticado

        }

        return new AuthenticationState(pessoa);
        // Principal é a pessoa que está dirigindo as ações e ela possui vários Claims (reivindicações, direitos, dados)
    }

    public async Task<AuthResponse> LoginAsync(string email, string senha)
    {
        var response = await _httpClient.PostAsJsonAsync($"auth/login?useCookies={true}", new { email, password = senha });

        if (response.IsSuccessStatusCode)
        {

            NotifyAuthenticationStateChanged(GetAuthenticationStateAsync()); // Notifica que o estado de autenticação mudou

            return new AuthResponse { Sucesso = true };
        }

        return new AuthResponse { Sucesso = false, Errors = ["Login/Senha inválidos"] };


    }

    public async Task LogoutAsync()
    {
        await _httpClient.PostAsync("auth/logout", null);
        NotifyAuthenticationStateChanged(GetAuthenticationStateAsync()); // Notifica que o estado de autenticação mudou
    } // false para não usar cookies

    public async Task<bool> VerificaAutenticado()
    {
        await GetAuthenticationStateAsync(); // Atualiza o estado de autenticação
        return autenticado; // Retorna o estado de autenticação atual
    }

}
