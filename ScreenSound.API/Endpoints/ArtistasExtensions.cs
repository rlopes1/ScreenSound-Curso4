﻿using Microsoft.AspNetCore.Mvc;
using ScreenSound.API.Requests;
using ScreenSound.API.Response;
using ScreenSound.Banco;
using ScreenSound.Modelos;
using ScreenSound.Shared.Dados.Modelos;
using System.Security.Claims;

namespace ScreenSound.API.Endpoints;

public static class ArtistasExtensions
{
    public static void AddEndPointsArtistas(this WebApplication app)
    {

        var groupBuilder = app.MapGroup("artistas")
            .RequireAuthorization()
            .WithTags("Artistas");

        #region Endpoint Artistas
        groupBuilder.MapGet("", ([FromServices] DAL<Artista> dal) =>
        {
            var listaDeArtistas = dal.Listar();
            if (listaDeArtistas is null)
            {
                return Results.NotFound();
            }
            var listaDeArtistaResponse = EntityListToResponseList(listaDeArtistas);
            return Results.Ok(listaDeArtistaResponse);
        });

        groupBuilder.MapGet("{nome}", ([FromServices] DAL<Artista> dal, string nome) =>
        {
            var artista = dal.RecuperarPor(a => a.Nome.ToUpper().Equals(nome.ToUpper()));
            if (artista is null)
            {
                return Results.NotFound();
            }
            return Results.Ok(EntityToResponse(artista));

        });

        groupBuilder.MapPost("", async ([FromServices]IHostEnvironment env,[FromServices] DAL<Artista> dal, [FromBody] ArtistaRequest artistaRequest) =>
        {
            
            var nome = artistaRequest.nome.Trim();
            var imagemArtista = DateTime.Now.ToString("ddMMyyyyhhss") + "." + nome + ".jpg";

            var path = Path.Combine(env.ContentRootPath,
                "wwwroot", "FotosPerfil", imagemArtista);

            using MemoryStream ms = new MemoryStream(Convert.FromBase64String(artistaRequest.fotoPerfil!));
            using FileStream fs = new(path, FileMode.Create);
            await ms.CopyToAsync(fs);

            var artista = new Artista(artistaRequest.nome, artistaRequest.bio) { FotoPerfil = $"/FotosPerfil/{imagemArtista}" };

            dal.Adicionar(artista);
            return Results.Ok();
        });

        groupBuilder.MapDelete("{id}", ([FromServices] DAL<Artista> dal, int id) => {
            var artista = dal.RecuperarPor(a => a.Id == id);
            if (artista is null)
            {
                return Results.NotFound();
            }
            dal.Deletar(artista);
            return Results.NoContent();

        });

        groupBuilder.MapPut("", ([FromServices] DAL<Artista> dal, [FromBody] ArtistaRequestEdit artistaRequestEdit) => {
            var artistaAAtualizar = dal.RecuperarPor(a => a.Id == artistaRequestEdit.Id);
            if (artistaAAtualizar is null)
            {
                return Results.NotFound();
            }
            artistaAAtualizar.Nome = artistaRequestEdit.nome;
            artistaAAtualizar.Bio = artistaRequestEdit.bio;        
            dal.Atualizar(artistaAAtualizar);
            return Results.Ok();
        });


        groupBuilder.MapPost("avaliacao", ([FromBody] AvaliacaoArtistaRequest request, [FromServices] DAL<Artista> dalArtista, HttpContext context, [FromServices] DAL<PessoaComAcesso> dalPessoa) =>
        {
            var artista = dalArtista.RecuperarPor(a => a.Id == request.ArtistaId);
            if( artista is null) return Results.NotFound();

            var email = context.User.Claims
            .FirstOrDefault(c=> c.Type == ClaimTypes.Email)?.Value
            ?? throw new InvalidOperationException("Pessoa não está conectada.");

            var pessoa = dalPessoa.RecuperarPor(p => p.Email.Equals(email))
            ?? throw new InvalidOperationException("Pessoa não está conectada");

      

            // Verifica se já existe uma avaliação para o artista feita pela pessoa.
            // Se não existir, adiciona uma nova nota para o artista.
            // Caso contrário, atualiza a nota existente.

            var avaliacao = artista.Avaliacoes.FirstOrDefault(a => a.ArtistaId == artista.Id && a.PessoaId == pessoa.Id);

            if (avaliacao is null)
            {
                artista.AdicionarNota(pessoa.Id, request.Nota);
            }
            else
            {
                avaliacao.Nota = request.Nota;
            }

            
            dalArtista.Atualizar(artista);

            return Results.Created();

        });



        groupBuilder.MapGet("artistas/{id}/avaliacao", ([FromServices] DAL<Artista> artistaDAL, int id, HttpContext context, DAL<PessoaComAcesso> dalPessoa) =>
        {
            var artista = artistaDAL.RecuperarPor(a => a.Id == id);
            if (artista is null) return Results.NotFound();

            var email = context.User.Claims
            .FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value
            ?? throw new InvalidOperationException("Pessoa não está conectada.");

            var pessoa = dalPessoa.RecuperarPor(p => p.Email.Equals(email))
            ?? throw new InvalidOperationException("Pessoa não está conectada");

            var avaliacao = artista.Avaliacoes.FirstOrDefault(a => a.ArtistaId == id && a.PessoaId == pessoa.Id);

            if (avaliacao is null) return Results.NotFound("Avaliação não encontrada para este artista.");

            return Results.Ok(new AvaliacaoArtistaResponse(id, avaliacao.Nota));




        });
        #endregion
    }

    private static ICollection<ArtistaResponse> EntityListToResponseList(IEnumerable<Artista> listaDeArtistas)
    {
        return listaDeArtistas.Select(a => EntityToResponse(a)).ToList();
    }

    private static ArtistaResponse EntityToResponse(Artista artista)
    {
        return new ArtistaResponse(artista.Id, artista.Nome, artista.Bio, artista.FotoPerfil)
        {
            Classificacao = artista.Avaliacoes.Select(a => a.Nota).DefaultIfEmpty(0).Average()
        };
    }

  
}
