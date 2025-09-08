#jwt
“Un JWT es un token de claims en formato JSON. Puede emitirse firmado (JWS), cifrado (JWE) o firmado y luego cifrado (JWE de un JWS).”

## Descripcion
JOSE es la “familia” de estándares. Dentro de ella:
- JWS = JSON Web Signature → firma (integridad + autenticidad).
- JWE = JSON Web Encryption → cifrado (confidencialidad + integridad del cifrado).
- JWT = JSON Web Token → formato de token (con claims) que puede ir firmado (JWS), cifrado (JWE) o ambas cosas (firmar y luego cifrar).

## En una frase
- JWS: garantiza que el contenido no fue alterado y quién lo firmó. No oculta el contenido.
- JWE: garantiza que solo el destinatario pueda leer el contenido (va cifrado).
- JWT: es el sobre con tus claims; puedes enviarlo firmado (JWS), cifrado (JWE) o firmado+­cifrado.


## Propiedades de seguridad
JWS:
- ✔ Integridad y autenticidad (si cambia un bit, la verificación falla).
- ✖ No confidencialidad: el payload es visible para cualquiera que tenga el token.

JWE:
- ✔ Confidencialidad + integridad del cifrado (AEAD, p.ej., GCM).
- El header protegido participa como AAD (si se altera, el tag no valida).

## ¿Cuándo usar cada uno?
- JWS (JWT firmado): acceso entre microservicios, access tokens, auditoría. Quieres saber quién lo emitió y que no se alteró.
	- Ej.: el Productor emite un JWT RS256; los servicios verifican con su clave pública.
- JWE (cifrado): datos/claims sensibles que no deben ser visibles en tránsito ni en logs.
	- Ej.: el Consumidor cifra con la pública del Productor; solo el Productor (privada) puede leer.
- Firmar + Cifrar (JWS→JWE): cuando necesitas ambas cosas: autenticidad del emisor y confidencialidad.
	- Patrón recomendado: firmar primero y luego cifrar.
	