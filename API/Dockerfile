FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
EXPOSE 5172

WORKDIR /app
COPY . .

ENTRYPOINT ["dotnet", "watch", "run"]