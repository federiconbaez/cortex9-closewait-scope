# Pre-registro del laboratorio de closewait-scope

Fijado antes de construir el arnés y antes de medir. Cualquier cambio posterior a este
archivo queda en el historial de git y se declara en el README.

## Umbrales (criterio de aceptación de la idea #49)

| Medida | Umbral |
|---|---|
| A. Causa de 3 fugas reproducidas | 3/3 correctas |
| B. Atribución proceso + clase de peer | >= 95% de 1.000 sockets |
| C. Overhead a 10.000 conexiones/s | < 2% |

## A. Tres fugas (corpus fijo)

Cada repro se corre 3 veces. Una repro cuenta como correcta solo si el grupo con más
sockets vistos entre los pids de la repro se clasifica con la causa esperada en las 3 corridas.
Observación: `watch --interval 0.5` durante 6 s, empezando junto con la carga.

1. `app_never_closes`: servidor Python que lee el request, responde y nunca cierra el
   socket. Cliente: una conexión nueva cada 50 ms que cierra al recibir la respuesta.
2. `worker_backlog_timeout`: gunicorn real, `-k gthread -w 1 --threads 1`, handler que
   duerme 2 s. 20 clientes que mandan el request y se rinden a los 0,3 s.
3. `upstream_keepalive_pool`: `requests.Session` real (urllib3, pool de 10) que hace
   una ráfaga de 10 requests concurrentes contra `http.server` HTTP/1.1 con timeout de
   inactividad de 1 s, y después queda ocioso. El servidor cierra las keepalive y el
   pool del cliente queda en CLOSE_WAIT. Es el patrón de nginx `upstream keepalive`
   reproducido con otro cliente con pool: nginx #2145 NO se reproduce en este repo.

Las reglas de clasificación son las de `closewait_scope/model.py:classify` en el
commit de este archivo. Advertencia fijada de antemano: las reglas y las repros son del
mismo autor, así que 3/3 es por construcción y no prueba cobertura de fugas reales ajenas.

## B. Atribución (1.000 sockets, semilla 49)

Dentro de un namespace de red sin privilegios (`unshare -rn`) con direcciones en `lo`:
127.0.0.1 y ::1 (loopback), 10.49.0.1 y fd00::49 (private), 203.0.113.49 y
2001:db8::49 (public; rangos de documentación usados como sustituto de internet).

- 5 servidores en procesos separados, puertos distintos. El servidor 5 hace fork de un
  hijo que hereda sus sockets: la verdad de terreno para esos sockets es {padre, hijo}.
- Un cliente abre 1.000 conexiones, con servidor y dirección de origen elegidos con
  `random.Random(49)`, y cierra cada una al instante: los servidores quedan con 1.000
  CLOSE_WAIT. Más 100 conexiones ESTABLISHED de señuelo que no deben aparecer.
- Verdad de terreno: cada servidor registra (ip remota, puerto remoto) de lo que acepta;
  la clase de peer sale de la tabla de direcciones de arriba.
- Un socket es correcto si aparece, el conjunto de pids coincide exactamente y la clase
  de peer coincide. Métrica: correctos / 1.000. Señuelos reportados: deben ser 0.

## C. Overhead a 10.000 conexiones/s

Carga: `lab/connload.c`, cliente y servidor en loopback, objetivo 10.000 conn/s durante
20 s; el servidor cierra primero (el cliente pasa por CLOSE_WAIT). 5 pares alternados
sin/con herramienta. Se reportan las conn/s logradas; si no llegan a 10.000 se dice.

- Userspace (box, sin root): `closewait-scope watch --interval 1` sobre todo el
  sistema. overhead = CPU de la herramienta / CPU de la carga en la misma corrida.
  Se reporta la mediana de 5 y el máximo.
- eBPF (CI con sudo): `bpftrace ebpf/closewait.bt` adjunto. overhead = (CPU carga con
  sonda + CPU bpftrace) / CPU carga sin sonda (mediana de pares) - 1. Si bpftrace no
  adjunta, el job falla.

Umbral < 2% para cada backend por separado.
