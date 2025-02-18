using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using ProductsAPI.Models;

var MyAllowSpecificOrigins = "_myAllowSpecificOrigins"; // CORS İÇİN
var builder = WebApplication.CreateBuilder(args);

//CORS İŞLEMLERİ (servis ve ön yüz geliştiricinin port noları vesayre farklı olursa tarayıcı hata verir. )
builder.Services.AddCors(Options => {
    Options.AddPolicy(MyAllowSpecificOrigins,policy =>{
        policy.AllowAnyOrigin() //bu güvenli bir işlem değil
        .AllowAnyHeader()
        .AllowAnyMethod();
    });
});


// Add services to the container.
builder.Services.AddControllers(); // ❗ Controllers eklenmeli
builder.Services.AddEndpointsApiExplorer();
//identtity tanımlaması

builder.Services.AddIdentity<AppUser,AppRole>().AddEntityFrameworkStores<ProductsContext>();

builder.Services.Configure<IdentityOptions>(options => {
    options.Password.RequiredLength = 6;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequireLowercase = false;
    options.Password.RequireUppercase = false;
    options.Password.RequireDigit = false;

    options.User.RequireUniqueEmail = true;
    options.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";

    options.Lockout.MaxFailedAccessAttempts =5;
    options.Lockout.DefaultLockoutTimeSpan=TimeSpan.FromMinutes(5);
});

builder.Services.AddAuthentication(x =>{
    x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(x=>{
    x.RequireHttpsMetadata=false;
    x.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer=false,
        //ValidIssuer="eren@gmail.com",
        ValidateAudience=false,
        //ValidAudience="",
        //ValidAudiences=new string[] {"a","b"},
        ValidateIssuerSigningKey=true,
        IssuerSigningKey =new SymmetricSecurityKey( Encoding.ASCII.GetBytes(builder.Configuration.GetSection("AppSettings:Secret").Value ?? "")),
        ValidateLifetime = true
    };
});

//swaggerda jwt tokeni verip authorize işlemini görüntüleyebileceğimiz arayüz yok o yüzden bunu yaptık postman kullanmadan burdan bakıcaz.
builder.Services.AddSwaggerGen(option =>
{
    option.SwaggerDoc("v1", new OpenApiInfo { Title = "Demo API", Version = "v1" });
    option.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        In = ParameterLocation.Header,
        Description = "Please enter a valid token",
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        BearerFormat = "JWT",
        Scheme = "Bearer"
    });
    option.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type=ReferenceType.SecurityScheme,
                    Id="Bearer"
                }
            },
            new string[]{}
        }
    });
});
builder.Services.AddDbContext<ProductsContext>(x => x.UseSqlite("Data Source=products.db")); //database ismin


var app = builder.Build();



// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication(); // biz yazdık
app.UseRouting(); // biz
app.UseCors(MyAllowSpecificOrigins); // CORS İÇİN


app.UseAuthorization(); // biz yazdık

app.MapControllers(); // ❗ Eksik olan satır

app.Run();
