"""El mago de las TTPs: arma un CSV con las tacticas y tecnicas de cada version de MITRE ATT&CK.

Uso:
    python json-magicianv2.py <carpeta_madre> [salida.csv]

La carpeta madre tiene que contener una subcarpeta por version del repo mitre/cti,
con el nombre terminado en la version. Por ejemplo:

    MITRE/
      cti-ATT-CK-v13.1/enterprise-attack/attack-pattern/*.json
      cti-ATT-CK-v14.1/enterprise-attack/attack-pattern/*.json

Cada release se baja de https://github.com/mitre/cti (boton Code -> Download ZIP
sobre el tag de la version que quieras).
"""

import csv
import json
import os
import sys

# Codigos de tactica. Se mantienen los nombres viejos junto con los nuevos porque
# el sentido del script es comparar versiones: MITRE renombro "defense-evasion"
# a "stealth" (TA0005) y sumo "defense-impairment" (TA0112), asi que una version
# vieja y una nueva usan nombres distintos para la misma tactica.
tacticas = {
    "reconnaissance": "TA0043",
    "resource-development": "TA0042",
    "initial-access": "TA0001",
    "execution": "TA0002",
    "persistence": "TA0003",
    "privilege-escalation": "TA0004",
    "defense-evasion": "TA0005",   # nombre viejo
    "stealth": "TA0005",           # nombre nuevo
    "defense-impairment": "TA0112",
    "credential-access": "TA0006",
    "discovery": "TA0007",
    "lateral-movement": "TA0008",
    "collection": "TA0009",
    "exfiltration": "TA0010",
    "command-and-control": "TA0011",
    "impact": "TA0040",
}


def calcularTacticaId(unaTactica):
    """Devuelve el codigo TAxxxx de una tactica, o 'Unknown' si no la conocemos."""
    return tacticas.get(unaTactica, "Unknown")


def calcularVersion(folder_name):
    """Saca el numero de version del nombre de la carpeta (cti-ATT-CK-v14.1 -> 14.1)."""
    if "-v" in folder_name:
        return folder_name.rsplit("-v", 1)[1]
    return folder_name


def leerTecnica(datos, version):
    """Arma las filas del CSV para un archivo attack-pattern de MITRE.

    Devuelve una fila por cada tactica a la que pertenece la tecnica. Las tecnicas
    revocadas no tienen tacticas y salen con 'N/A'.
    """
    objeto = datos["objects"][0]
    ttp_id = str(objeto["external_references"][0]["external_id"])
    nombre = str(objeto["name"])

    if "." in ttp_id:
        # Es una subtecnica: MITRE no diferencia el titulo, asi que va en las dos.
        tecnicaId = ttp_id.split(".")[0]
        tecnicaTit = ""
        subtecnicaId = ttp_id
        subtecnicaTit = nombre
    else:
        tecnicaId = ttp_id
        tecnicaTit = nombre
        subtecnicaId = ""
        subtecnicaTit = ""

    fases = objeto.get("kill_chain_phases", [])
    if not fases:
        return [{
            "Version": version, "Tactica": "N/A", "TacticaID": "N/A",
            "Tecnica": tecnicaTit, "TecnicaID": tecnicaId,
            "Subtecnica": subtecnicaTit, "SubtecnicaID": subtecnicaId,
        }]

    filas = []
    for unaFase in fases:
        tacticaDes = str(unaFase["phase_name"])
        filas.append({
            "Version": version, "Tactica": tacticaDes,
            "TacticaID": calcularTacticaId(tacticaDes),
            "Tecnica": tecnicaTit, "TecnicaID": tecnicaId,
            "Subtecnica": subtecnicaTit, "SubtecnicaID": subtecnicaId,
        })
    return filas


def calcularTTPs(path_main):
    """Recorre cada carpeta de version y devuelve todas las TTPs encontradas."""
    lista_ttps = []

    for folder_name in sorted(os.listdir(path_main)):
        folder_path = os.path.join(path_main, folder_name)
        if not os.path.isdir(folder_path):
            continue

        folder_current = os.path.join(folder_path, "enterprise-attack", "attack-pattern")
        if not os.path.isdir(folder_current):
            print(f"[!] {folder_name}: no encontre enterprise-attack/attack-pattern, la salteo")
            continue

        version = calcularVersion(folder_name)
        archivos = [f for f in os.listdir(folder_current) if f.endswith(".json")]
        print(f"[+] {folder_name} (version {version}): {len(archivos)} archivos")

        for file_name in archivos:
            with open(os.path.join(folder_current, file_name), "rb") as file_current:
                datos = json.load(file_current)
            lista_ttps.extend(leerTecnica(datos, version))

    return lista_ttps


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    path_main = sys.argv[1]
    salida = sys.argv[2] if len(sys.argv) > 2 else "ttps.csv"

    if not os.path.isdir(path_main):
        print(f"[x] No existe la carpeta: {path_main}")
        sys.exit(1)

    lista = calcularTTPs(path_main)
    if not lista:
        print("[x] No encontre ninguna TTP. Revisa que la estructura de carpetas sea la esperada.")
        sys.exit(1)

    columnas = ["Version", "Tactica", "TacticaID", "Tecnica", "TecnicaID", "Subtecnica", "SubtecnicaID"]
    with open(salida, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=columnas)
        writer.writeheader()
        writer.writerows(lista)

    desconocidas = sorted({t["Tactica"] for t in lista if t["TacticaID"] == "Unknown"})
    if desconocidas:
        print(f"[!] Tacticas sin codigo (agregalas al diccionario): {', '.join(desconocidas)}")

    print(f"[+] Listo: {len(lista)} filas en {salida}")


if __name__ == "__main__":
    main()
