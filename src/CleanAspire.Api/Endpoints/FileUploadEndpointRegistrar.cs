﻿// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.


using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Http.HttpResults;
using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using CleanAspire.Application.Common.Interfaces;
using SixLabors.ImageSharp.Formats.Png;
using SixLabors.ImageSharp.Processing;
using SixLabors.ImageSharp;
using System.IO;

namespace CleanAspire.Api.Endpoints;

public class FileUploadEndpointRegistrar : IEndpointRegistrar
{
    public void RegisterRoutes(IEndpointRouteBuilder routes)
    {
        var group = routes.MapGroup("/upload").WithTags("File Upload");

        group.MapPost("/", async ([FromForm] FileUploadRequest request, [FromServices] IServiceProvider sp) =>
        {
            var response = new List<FileUploadResponse>();
            var uploadService = sp.GetRequiredService<IUploadService>();
            foreach (var file in request.Files)
            {
                var filestream = file.OpenReadStream();
                var stream = new MemoryStream();
                await filestream.CopyToAsync(stream);
                stream.Position = 0;
                var size = stream.Length;
                var uploadRequest = new UploadRequest(
                    file.FileName,
                    UploadType.Document,
                    stream.ToArray(),
                    request.Overwrite,
                    Path.GetExtension(file.FileName),
                    request.Folder
                );
                var result = await uploadService.UploadAsync(uploadRequest);
                response.Add(new FileUploadResponse { Path = result, Size = size });
            }
            return TypedResults.Ok(response);
        }).Accepts<FileUploadRequest>("multipart/form-data")
        .DisableAntiforgery()
        .WithMetadata(new ConsumesAttribute("multipart/form-data"))
        .WithSummary("Upload files to the server")
        .WithDescription("Allows uploading multiple files to a specific folder on the server.");

        group.MapPost("/image", async ([FromForm] ImageUploadRequest request, [FromServices] IServiceProvider sp) =>
        {
            var response = new List<FileUploadResponse>();
            var uploadService = sp.GetRequiredService<IUploadService>();
            foreach (var file in request.Files)
            {
                var filestream = file.OpenReadStream();
                var imgstream = new MemoryStream();
                await filestream.CopyToAsync(imgstream);
                imgstream.Position = 0;
                if (request.CropSize != null)
                {
                    using (var outStream = new MemoryStream())
                    {
                        using (var image = SixLabors.ImageSharp.Image.Load(imgstream))
                        {
                            image.Mutate(i => i.Resize(new ResizeOptions { Mode = ResizeMode.Crop, Size = new Size(request.CropSize.Width, request.CropSize.Height) }));
                            image.Save(outStream, PngFormat.Instance);
                            var result = await uploadService.UploadAsync(new UploadRequest(
                                file.FileName,
                                UploadType.Images,
                                outStream.ToArray(),
                                request.Overwrite,
                                Path.GetExtension(file.FileName),
                                request.Folder
                            ));
                            response.Add(new FileUploadResponse { Path = result, Size = (int)outStream.Length });
                        }
                    }
                }
                else
                {
                    var uploadRequest = new UploadRequest(
                        file.FileName,
                        UploadType.Images,
                        imgstream.ToArray(),
                        request.Overwrite,
                        Path.GetExtension(file.FileName),
                        request.Folder
                    );
                    var result = await uploadService.UploadAsync(uploadRequest);
                    response.Add(new FileUploadResponse { Path = result, Size = (int)imgstream.Length });
                }

            }

            return TypedResults.Ok(response);
        }).Accepts<ImageUploadRequest>("multipart/form-data")
        .DisableAntiforgery()
        .WithMetadata(new ConsumesAttribute("multipart/form-data"))
        .WithSummary("Upload images to the server with cropping options")
        .WithDescription("Allows uploading multiple image files with optional cropping options to a specific folder on the server.");
    }


    public class FileUploadRequest
    {
        /// <summary>
        /// Represents a request for uploading files to a specific folder.
        /// </summary>
        [Required]
        [StringLength(255, ErrorMessage = "Folder name cannot exceed 255 characters.")]
        [Description("The folder path where the files should be uploaded.")]
        public string Folder { get; set; } = string.Empty;

        [Description("Indicates whether to overwrite existing files.")]
        public bool Overwrite { get; set; }

        [Required]
        [MinLength(1, ErrorMessage = "At least one file must be uploaded.")]
        [Description("The list of files to be uploaded.")]
        public List<IFormFile> Files { get; set; } = new();
    }
    public class FileUploadResponse
    {
        /// <summary>
        /// The path where the uploaded file is saved.
        /// </summary>  
        [Description("The path where the uploaded file is saved.")]
        public string Path { get; set; } = string.Empty;

        /// <summary>
        /// The size of the uploaded file in bytes.
        /// </summary>
        [Description("The size of the uploaded file in bytes.")]
        public long Size { get; set; }
    }


    public class ImageUploadRequest
    {
        /// <summary>
        /// Represents a request for uploading image files to a specific folder, with an option to crop.
        /// </summary>
        [Required]
        [StringLength(255, ErrorMessage = "Folder name cannot exceed 255 characters.")]
        [Description("The folder path where the files should be uploaded.")]
        public string Folder { get; set; } = string.Empty;

        [Description("Indicates whether to overwrite existing files.")]
        public bool Overwrite { get; set; }

        [Required]
        [MinLength(1, ErrorMessage = "At least one file must be uploaded.")]
        [Description("The list of files to be uploaded.")]
        public List<IFormFile> Files { get; set; } = new();

        [Description("The desired crop size for the uploaded image.")]
        public CropSize? CropSize { get; set; }
    }

    public class CropSize
    {
        /// <summary>
        /// Represents the desired size for cropping an image.
        /// </summary>
        [Range(1, int.MaxValue, ErrorMessage = "Width must be greater than 0.")]
        [Description("The width of the cropped image.")]
        public int Width { get; set; }

        [Range(1, int.MaxValue, ErrorMessage = "Height must be greater than 0.")]
        [Description("The height of the cropped image.")]
        public int Height { get; set; }
    }

}



