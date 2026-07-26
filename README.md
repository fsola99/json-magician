# json-magician

El mago de las TTPs: arma un CSV con todas las tacticas, tecnicas y subtecnicas de
**varias versiones de MITRE ATT&CK a la vez**, para poder compararlas entre si.

<img src="https://i.ibb.co/0DhxKTQ/output.png"/>

## Uso

```bash
python json-magicianv2.py <carpeta_madre> [salida.csv]
```

La carpeta madre tiene que tener una subcarpeta por version, con el nombre terminado
en la version:

```
MITRE/
  cti-ATT-CK-v13.1/enterprise-attack/attack-pattern/*.json
  cti-ATT-CK-v14.1/enterprise-attack/attack-pattern/*.json
```

Cada release se baja de [mitre/cti](https://github.com/mitre/cti): elegis el tag de
la version que quieras y la descargas como ZIP.

Si no pasas el segundo argumento, escribe en `ttps.csv`.

## Salida

Una fila por cada par tecnica/tactica, ya que una misma tecnica puede pertenecer a
varias tacticas:

| Version | Tactica | TacticaID | Tecnica | TecnicaID | Subtecnica | SubtecnicaID |
|---|---|---|---|---|---|---|
| 14.1 | persistence | TA0003 | | T1053 | Scheduled Task | T1053.005 |
| 14.1 | stealth | TA0005 | Indicator Removal from Tools | T1066 | | |

Las tecnicas revocadas no tienen tacticas y salen con `N/A`.

## Sobre los nombres de las tacticas

El diccionario de tacticas guarda los nombres viejos **y** los nuevos a proposito.
MITRE renombro `defense-evasion` a `stealth` (las dos son TA0005) y sumo
`defense-impairment` (TA0112), asi que una version vieja y una nueva le dicen
distinto a la misma tactica. Como el script justamente compara versiones, necesita
entender las dos.

Si aparece una tactica que no esta en el diccionario, el script la marca como
`Unknown` y avisa al terminar cual fue, para poder agregarla.
