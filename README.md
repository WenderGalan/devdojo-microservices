# devdojo-microservices

Projeto referente ao curso do canal [DEVDOJO](https://www.youtube.com/watch?v=vxeMnM15gsI&list=PL62G310vn6nH_iMQoPMhIlK_ey1npyUUl&index=1) do youtube.

O código está todo comentado para tentar sanar eventuais dúvidas sobre.

Foram implementados os seguintes módulos:
- gateway: Serviço de Router / Gateway
- discovery: Serviço de Service Discovery
- auth: Serviço de autenticação
- token: Serviço para geração de tokens assinados / criptografados
- core: módulo onde ficam as classes comuns às demais classes. Nesse módulo estão o model e o repository.
- course: microserviço de negócio. Nesse módulo fica api rest para acessar os recursos.

Para rodar o projeto se faz necessário subir o banco de dados. Existe um stack.yml dentro do package course para subir o banco de dados no docker, só abrir a pasta e rodar o comando abaixo:

````
docker-compose -f stack.yml up
````

Arquitetura dos microservices:

````
--------------
 Client Side
--------------
    |
    |REST
    |
---------------------------              --------------------------
 Router and Filter Gateway   <-Fetches->  Service Discovery Server
---------------------------              --------------------------  
único ponto de entrada para receber requisições REST


DMZ
---------------------------------------------    
----------------  ----------  ---------- ---------- ----------
 Authentication    service1    service1   service2   service3
    Service       ----------  ---------- ---------- ----------
----------------       |            |         |         |
       |               v            v         |         |
       v                --------------        v         v
      ( DB )                 (DB)            (DB)      (DB) 
````

Caso tenha alguma dúvida referente ao código pode-se consultar no README do projeto abaixo:

https://github.com/joliveira-git/devdojo-microservices