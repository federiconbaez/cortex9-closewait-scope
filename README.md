# closewait-scope

Diagnóstico de sockets TCP en `CLOSE_WAIT` en Linux: **qué proceso** los tiene, **contra
quién** (proxy local, red privada o internet), **desde hace cuánto**, **a qué ritmo
crecen** y **qué causa conocida** encaja, con comparación antes/después de un cambio.

`ss` y `lsof` dan una foto instantánea sin historia ni causa. Este repo es el MVP de
un día de la idea #49: una CLI en Python sin dependencias que corre sin root, más un
backend eBPF opcional (bpftrace) para medir la edad exacta.

## Uso

```bash
python -m closewait_scope snapshot                 # foto actual
python -m closewait_scope watch --interval 1 --duration 30 [--pid 123,456] [--json]
python -m closewait_scope compare antes.json despues.json   # veredicto mejoro/empeoro/igual
sudo python -m closewait_scope ebpf --duration 10  # eventos de entrada/salida de CLOSE_WAIT (root)
```

Salida de `watch` por grupo (pid, rol, puerto, clase de peer): cantidad actual, vistos,
salidos, tasa de fuga por segundo, histograma de edad, causa probable y sugerencia.

## Cómo decide

- **Lectura**: netlink `sock_diag` filtrando `CLOSE_WAIT` en el kernel (sin root); si no
  está disponible, `/proc/net/tcp{,6}`.
- **Atribución**: inode del socket contra `/proc/<pid>/fd/*`. Un socket compartido por
  `fork` se atribuye al conjunto de pids.
- **Rol**: servidor si el puerto local es un `LISTEN` del mismo proceso; si no, cliente.
- **Causa** (`closewait_scope/model.py:classify`):
  - lado cliente → `upstream_keepalive_pool` (pool keepalive hacia un upstream que ya cerró);
  - lado servidor con payload sin leer en ≥50% de los sockets → `worker_backlog_timeout`
    (el peer se rindió mientras la conexión esperaba un worker);
  - lado servidor, request leído, sin salidas y cuenta que no baja → `app_never_closes`.
- Detalle medido en la box: en `CLOSE_WAIT` el kernel cuenta el FIN como 1 byte de
  `rx_queue` mientras la app no leyó el EOF. Payload sin leer es `rx_queue > 1`.

## Resultados

Umbrales y corpus fijados en [`lab/PREREGISTRO.md`](lab/PREREGISTRO.md) antes de escribir
el arnés. Corrida completa en la box (kernel 6.12.94, 8 CPU, Python 3.13.5) el
29/10/2026 a las 10:41 ART; JSON en [`results/box-2026-10-29.json`](results/box-2026-10-29.json).
Reproducir: `pip install gunicorn==26.2.0 requests && python -m lab.measure`.

| Medida | Umbral | Medido | Veredicto |
|---|---|---|---|
| A. Causa de 3 fugas reproducidas, 3 corridas c/u | 3/3 | 3/3 (9/9 corridas) | cumplido, **por construcción** |
| B. Atribución pid + clase de peer, 1.000 CLOSE_WAIT | ≥ 95% | 1000/1000, 0 señuelos reportados | cumplido, **por construcción** |
| C. Overhead userspace a 10.000 conn/s, 5 pares | < 2% | mediana 1,04%, máximo 1,09% | cumplido |
| C. Overhead eBPF a 10.000 conn/s | < 2% | lo mide el job `ebpf` de CI (artefacto `results-ebpf`) | ver CI |

Detalle:

- **A.** `app_never_closes`: 109 sockets vistos, 0 salidos, tasa de fuga 17,9–19,6/s.
  `worker_backlog_timeout` con gunicorn 26.2.0 real (`gthread`, 1 thread): 20 vistos,
  2 salidos, 95% con payload sin leer. `upstream_keepalive_pool` con `requests`/urllib3
  real: 10 sockets del lado cliente, uno por conexión del pool.
- **B.** 324 loopback, 343 privadas y 333 públicas, IPv4 e IPv6, más 100 conexiones
  `ESTABLISHED` de señuelo y un proceso hijo que hereda sockets. Escaneo con netlink: 29 ms.
- **C.** Carga `lab/connload.c` sostenida en 9.999,6–9.999,8 conn/s. `watch --interval 1`
  sobre todo el sistema gastó 0,095–0,107 s de CPU por corrida de 20 s, contra 9,1–10,8 s
  de CPU de la carga. La CPU de la carga varió entre 9,1 y 10,8 s entre corridas, mucho más que el costo de la
  herramienta, así que el efecto sobre la carga en sí no se puede resolver con 5 pares; la
  métrica pre-registrada es CPU de la herramienta / CPU de la carga.

### Por qué "por construcción"

Las reglas de causa, las repros y la verdad de terreno de atribución las escribió el mismo
autor el mismo día. 3/3 y 1000/1000 muestran que la herramienta hace lo que dice sobre
estos escenarios, no que reconozca fugas de producción ajenas.

### Cambio de arnés después del pre-registro

La primera corrida completa quedó inválida: la carga del experimento C cayó de 9.999 a
2.031 y 7,5 conn/s tras el primer par por `TIME_WAIT` acumulado en loopback. Se cambió
el cierre (el servidor hace `shutdown(SHUT_WR)`, el cliente pasa por `CLOSE_WAIT` y
cierra con RST) sin tocar métricas ni umbrales. Commit `fix(lab)` en el historial.

## Alcance: lo que NO está verificado

- **nginx #2145 no se reprodujo.** La causa `upstream_keepalive_pool` se probó con un pool
  de urllib3, no con nginx `upstream keepalive`.
- Ninguna fuga de producción real; ningún servidor ajeno.
- La edad desde userspace es **cota inferior** con resolución igual al intervalo. La edad
  exacta sale del backend eBPF, que solo corre con root (en CI); la box tiene
  `unprivileged_bpf_disabled=2`.
- La CLI no une todavía los eventos eBPF con la atribución por proceso: `ebpf` vuelca
  eventos por puertos.
- Solo ve el namespace de red propio: contenedores en otro netns requieren correrla adentro.
- Atribuir sockets de procesos de otros usuarios requiere root (se reporta cuántos
  procesos no se pudieron leer).
- Overhead userspace medido en una sola máquina virtual compartida; no se midió en hardware
  físico ni con decenas de miles de procesos.
- La comparación antes/después usa tolerancia fija de 20% sin test estadístico.

## Tests

```bash
python -m tests.run            # 19 tests; un test salteado hace fallar la corrida
sudo python3 -m tests.ebpf_check   # backend eBPF (root + bpftrace)
```

CI: tests y laboratorio completo en `ubuntu-24.04`, y job `ebpf` con sudo que falla si
bpftrace no adjunta o no ve la entrada y salida de `CLOSE_WAIT`.

## Licencia

Apache-2.0.
