#requires -version 4.0
<#
    Audit des fichiers : qui a supprimé / créé quel fichier ou dossier, et quand.

    Lancement (PowerShell ouvert en administrateur) :
        powershell -ExecutionPolicy Bypass -STA -File .\AuditSuppressions.ps1

    Sources (journal Sécurité des serveurs) :
      Suppressions
        - 4663 avec AccessMask 0x10000 (DELETE) : utilisateur + chemin
        - 4660 "Un objet a été supprimé" : confirme la suppression (rapproché via ProcessId + HandleId)
      Créations
        - 4663 avec AccessMask 0x2 / 0x4 (écriture, ajout de fichier, ajout de sous-dossier)
        - Windows ne distingue pas création et modification : une création est confirmée en vérifiant
          sur le disque que l'élément a été créé au moment de l'événement (date de création NTFS).
          Cela retrouve aussi le nom final d'un élément renommé juste après sa création
          ("Nouveau dossier" -> "Projets 2027", fichiers temporaires d'Office -> "Budget.xlsx").
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

# Fichiers parasites créés/supprimés en permanence par Office, l'Explorateur, etc.
# (le dernier motif = fichiers temporaires d'Excel : 8 caractères hexadécimaux sans extension)
$NoiseRegex = '(\\~\$[^\\]*$)|(\.tmp$)|(\\~WRL\d+)|(\\Thumbs\.db$)|(\\desktop\.ini$)|(\\\.~lock\.)|(\\(?=[0-9A-F]*[A-F])[0-9A-F]{8}$)'

$script:FsErrors  = 0
$script:Searching = $false
$script:Cancel    = $false

# ---------------------------------------------------------------- Fonctions utilitaires

function Test-IsLocal([string]$Server) {
    (-not $Server) -or ($Server -in @('localhost', '.', $env:COMPUTERNAME))
}

function Get-TimeFilter([datetime]$From, [datetime]$To) {
    $f = $From.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    $t = $To.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    "TimeCreated[@SystemTime>='$f' and @SystemTime<='$t']"
}

# Lecteur d'événements en flux : un événement à la fois, seulement les champs demandés,
# sans formatage du message (Get-WinEvent charge tout en mémoire et plante sur les gros journaux)
function New-EventReader {
    param([string]$Server, [string]$XPath, [string[]]$Fields)
    # New-Object plutôt que ::new() : compatible PowerShell 4 (Windows Server 2012 R2)
    $q = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery -ArgumentList 'Security', ([System.Diagnostics.Eventing.Reader.PathType]::LogName), $XPath
    if (-not (Test-IsLocal $Server)) { $q.Session = New-Object System.Diagnostics.Eventing.Reader.EventLogSession -ArgumentList $Server }
    $q.ReverseDirection = $true   # du plus récent au plus ancien
    [string[]]$paths = $Fields | ForEach-Object { "Event/EventData/Data[@Name='$_']" }
    $r = New-Object System.Diagnostics.Eventing.Reader.EventLogReader -ArgumentList $q
    $r.BatchSize = 512
    $sel = New-Object System.Diagnostics.Eventing.Reader.EventLogPropertySelector -ArgumentList (, $paths)
    @{ Reader = $r; Selector = $sel }
}

function Update-Progress([string]$Text) {
    $status.Text = $Text
    [System.Windows.Forms.Application]::DoEvents()
}

function Split-Chemin([string]$Path) {
    $i = $Path.LastIndexOf('\')
    if ($i -lt 0) { return @('', $Path) }
    @($Path.Substring(0, $i), $Path.Substring($i + 1))
}

# "D:\Partages\x" vu depuis un autre poste -> "\\SERVEUR\D$\Partages\x"
function Convert-ToUnc([string]$Server, [string]$Path) {
    if ((Test-IsLocal $Server) -or $Path -notmatch '^([A-Za-z]):\\(.*)$') { return $Path }
    '\\{0}\{1}$\{2}' -f $Server, $Matches[1], $Matches[2]
}

# Contenu d'un dossier indexé par seconde de création (mis en cache pendant une recherche)
function Get-DirIndex {
    param([string]$Server, [string]$LocalDir, [hashtable]$Cache)
    $key = $LocalDir.ToLowerInvariant()
    if ($Cache.ContainsKey($key)) { return $Cache[$key] }

    $idx = @{ BySecond = @{}; ByName = @{} }
    $dir = if ($LocalDir.EndsWith(':')) { "$LocalDir\" } else { $LocalDir }
    try {
        $di = New-Object System.IO.DirectoryInfo (Convert-ToUnc $Server $dir)
        if ($di.Exists) {
            foreach ($fi in $di.EnumerateFileSystemInfos()) {
                $item = [pscustomobject]@{
                    Path    = [System.IO.Path]::Combine($dir, $fi.Name)
                    Created = $fi.CreationTime
                    IsDir   = [bool]($fi.Attributes -band [System.IO.FileAttributes]::Directory)
                }
                $idx.ByName[$fi.Name.ToLowerInvariant()] = $item
                $sec = [long][math]::Floor($fi.CreationTime.Ticks / 1e7)
                if (-not $idx.BySecond.ContainsKey($sec)) { $idx.BySecond[$sec] = New-Object System.Collections.ArrayList }
                [void]$idx.BySecond[$sec].Add($item)
            }
        }
    }
    catch { $script:FsErrors++ }
    $Cache[$key] = $idx
    $idx
}

# ---------------------------------------------------------------- Lecture du journal

# Le journal Sécurité n'est pas indexé par date : un filtre "à partir de telle date" oblige Windows
# à parcourir tout le fichier (plusieurs Go). On lit donc en un seul passage, du plus récent au plus
# ancien, et on s'arrête dès qu'on a dépassé le début de la période : seule la période est parcourue.
function Get-FileEvents {
    param(
        [string]$Server, [datetime]$From, [datetime]$To,
        [bool]$WantDeletions, [bool]$WantCreations, [bool]$IncludeUnconfirmed, [bool]$HideNoise
    )

    # Borne haute seulement (+5 min pour les 4660, émis à la fermeture du fichier).
    # Surtout pas de borne basse dans le filtre : le lecteur continuerait jusqu'au début du journal.
    $upper  = $To.AddMinutes(5).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    $xpath  = "*[System[(EventID=4660 or EventID=4663) and TimeCreated[@SystemTime<='$upper']]]"
    $fields = @('SubjectUserName', 'SubjectDomainName', 'ObjectName', 'ProcessId', 'HandleId', 'ProcessName', 'AccessMask')
    $rd = New-EventReader $Server $xpath $fields

    $older    = 0
    $deleted  = @{}                                               # 4660 : "ProcessId|HandleId" -> dates
    $delCands = New-Object System.Collections.Generic.List[object]  # 4663 DELETE
    $cands    = @{}                                               # 4663 écriture (créations possibles)
    $n = 0
    try {
        while (-not $script:Cancel -and $null -ne ($e = $rd.Reader.ReadEvent())) {
            try {
                $id   = $e.Id
                $time = [datetime]$e.TimeCreated
                $v    = $e.GetPropertyValues($rd.Selector)
            }
            finally { $e.Dispose() }

            # Début de période dépassé : on s'arrête, mais seulement après 200 événements trop anciens
            # d'affilée (au démarrage, Windows écrit parfois des événements en retard, hors ordre).
            if ($time -lt $From) {
                if (++$older -ge 200) { break }
                continue
            }
            $older = 0
            if ((++$n % 2000) -eq 0) {
                Update-Progress ('Lecture du journal de {0} : {1} événements, arrivé au {2:dd/MM/yyyy HH:mm}' -f $Server, $n, $time)
            }

            if ($id -eq 4660) {
                if ($WantDeletions) {
                    $k = '{0}|{1}' -f $v[3], $v[4]
                    if (-not $deleted.ContainsKey($k)) { $deleted[$k] = New-Object System.Collections.Generic.List[datetime] }
                    $deleted[$k].Add($time)
                }
                continue
            }

            if ($time -gt $To) { continue }
            $user = [string]$v[0]
            if ($HideNoise -and $user.EndsWith('$')) { continue }  # comptes ordinateurs / système
            $mask = [long]$v[6]
            $path = [string]$v[2]
            $ev = [pscustomobject]@{
                Date    = $time
                User    = ('{0}\{1}' -f $v[1], $user)
                Path    = $path
                Process = [string]$v[5]
                Key     = ('{0}|{1}' -f $v[3], $v[4])
            }
            if ($WantDeletions -and ($mask -band 0x10000)) { $delCands.Add($ev) }
            elseif ($WantCreations -and ($mask -band 0x6)) {
                $k = '{0:yyyyMMddHHmmss}|{1}' -f $time, $path.ToLowerInvariant()
                if (-not $cands.ContainsKey($k)) { $cands[$k] = $ev }
            }
        }
    }
    finally { $rd.Reader.Dispose() }

    # --- Suppressions : confirmées par un 4660 sur le même ProcessId + HandleId
    if ($WantDeletions) {
        $seen = New-Object System.Collections.Generic.HashSet[string]
        foreach ($c in $delCands) {
            if ($HideNoise -and $c.Path -match $NoiseRegex) { continue }
            $confirmed = $false
            if ($deleted.ContainsKey($c.Key)) {
                foreach ($d in $deleted[$c.Key]) {
                    $s = ($d - $c.Date).TotalSeconds
                    if ($s -ge 0 -and $s -le 300) { $confirmed = $true; break }
                }
            }
            if (-not $confirmed -and -not $IncludeUnconfirmed) { continue }

            # Une même suppression peut produire plusieurs 4663 : dédoublonnage
            if (-not $seen.Add(('{0:yyyyMMddHHmmss}|{1}|{2}' -f $c.Date, $c.User, $c.Path))) { continue }

            $parent, $name = Split-Chemin $c.Path
            [pscustomobject]@{
                Date        = $c.Date
                Action      = if ($confirmed) { 'Supprimé' } else { 'Supprimé / renommé / déplacé' }
                Utilisateur = $c.User
                Nom         = $name
                Emplacement = $parent
                Serveur     = $Server
                Processus   = $c.Process
                Chemin      = $c.Path
            }
        }
    }

    if ($WantCreations -and $cands.Count -gt 0 -and -not $script:Cancel) {
        Resolve-Creations -Server $Server -Cands $cands -HideNoise $HideNoise
    }
}

# Windows ne distingue pas création et modification : on vérifie sur le disque quel élément a été
# créé à ce moment-là, à cet endroit (l'élément lui-même, ses voisins s'il a été renommé juste après,
# et son contenu si c'est un dossier). Pour chaque élément, on garde l'événement le plus proche.
function Resolve-Creations {
    param([string]$Server, [hashtable]$Cands, [bool]$HideNoise)

    $cache = @{}
    $best  = @{}
    $n = 0
    foreach ($c in $Cands.Values) {
        if ($script:Cancel) { break }
        $n++
        if ($n % 200 -eq 0) { Update-Progress "Vérification des créations sur $Server : $n / $($Cands.Count)" }

        $parent, $name = Split-Chemin $c.Path
        if (-not $parent) { continue }

        $dirs = @($parent)
        $pidx = Get-DirIndex $Server $parent $cache
        $self = $pidx.ByName[$name.ToLowerInvariant()]
        if ($self -and $self.IsDir) { $dirs += $c.Path }

        $sec0 = [long][math]::Floor($c.Date.Ticks / 1e7)
        foreach ($d in $dirs) {
            $idx = Get-DirIndex $Server $d $cache
            for ($s = $sec0 - 5; $s -le $sec0 + 5; $s++) {
                $list = $idx.BySecond[$s]
                if (-not $list) { continue }
                foreach ($item in $list) {
                    if ($HideNoise -and $item.Path -match $NoiseRegex) { continue }
                    $score = [math]::Abs(($item.Created - $c.Date).TotalSeconds)
                    if ($item.Path -ne $c.Path) { $score += 100 }   # priorité à la correspondance exacte
                    $ik = $item.Path.ToLowerInvariant()
                    if (-not $best.ContainsKey($ik) -or $score -lt $best[$ik].Score) {
                        $best[$ik] = @{ Score = $score; Item = $item; Event = $c }
                    }
                }
            }
        }
    }

    foreach ($b in $best.Values) {
        $parent, $name = Split-Chemin $b.Item.Path
        [pscustomobject]@{
            Date        = $b.Event.Date
            Action      = if ($b.Item.IsDir) { 'Dossier créé' } else { 'Fichier créé' }
            Utilisateur = $b.Event.User
            Nom         = $name
            Emplacement = $parent
            Serveur     = $Server
            Processus   = $b.Event.Process
            Chemin      = $b.Item.Path
        }
    }
}

# ---------------------------------------------------------------- Interface

$Theme = @{
    Header    = [System.Drawing.Color]::FromArgb(24, 36, 61)
    HeaderSub = [System.Drawing.Color]::FromArgb(160, 174, 200)
    Accent    = [System.Drawing.Color]::FromArgb(37, 99, 235)
    AccentHov = [System.Drawing.Color]::FromArgb(29, 78, 216)
    Panel     = [System.Drawing.Color]::FromArgb(246, 247, 249)
    Border    = [System.Drawing.Color]::FromArgb(222, 226, 232)
    Text      = [System.Drawing.Color]::FromArgb(31, 41, 55)
    Muted     = [System.Drawing.Color]::FromArgb(107, 114, 128)
    Del       = [System.Drawing.Color]::FromArgb(185, 28, 28)
    DelBg     = [System.Drawing.Color]::FromArgb(254, 226, 226)
    New       = [System.Drawing.Color]::FromArgb(21, 128, 61)
    NewBg     = [System.Drawing.Color]::FromArgb(220, 252, 231)
    Select    = [System.Drawing.Color]::FromArgb(219, 234, 254)
    White     = [System.Drawing.Color]::White
}
$FontUi    = New-Object System.Drawing.Font('Segoe UI', 9)
$FontInput = New-Object System.Drawing.Font('Segoe UI', 10)
$FontBold  = New-Object System.Drawing.Font('Segoe UI Semibold', 9)
$FontTitle = New-Object System.Drawing.Font('Segoe UI Semibold', 16)
$FontCount = New-Object System.Drawing.Font('Segoe UI Semibold', 10)

function New-Label($Parent, $Text, $X, $Y, [switch]$Muted) {
    $l = New-Object System.Windows.Forms.Label
    $l.Text = $Text; $l.AutoSize = $true; $l.BackColor = 'Transparent'
    $l.Location = New-Object System.Drawing.Point($X, $Y)
    $l.ForeColor = if ($Muted) { $Theme.Muted } else { $Theme.Text }
    $Parent.Controls.Add($l); $l
}

function New-TextBox($Parent, $X, $Y, $W) {
    $t = New-Object System.Windows.Forms.TextBox
    $t.Location = New-Object System.Drawing.Point($X, $Y)
    $t.Width = $W; $t.Font = $FontInput; $t.BorderStyle = 'FixedSingle'
    $Parent.Controls.Add($t); $t
}

function New-DatePicker($Parent, $X, $Y, $Value) {
    $d = New-Object System.Windows.Forms.DateTimePicker
    $d.Location = New-Object System.Drawing.Point($X, $Y)
    $d.Width = 150; $d.Font = $FontInput
    $d.Format = 'Custom'; $d.CustomFormat = 'dd/MM/yyyy HH:mm'
    $d.Value = $Value
    $Parent.Controls.Add($d); $d
}

function New-Check($Parent, $Text, $X, $Y, $Checked) {
    $c = New-Object System.Windows.Forms.CheckBox
    $c.Text = $Text; $c.Checked = $Checked; $c.AutoSize = $true
    $c.ForeColor = $Theme.Text; $c.BackColor = 'Transparent'
    $c.Location = New-Object System.Drawing.Point($X, $Y)
    $Parent.Controls.Add($c); $c
}

function New-Button($Parent, $Text, $X, $Y, $W, $H, [switch]$Primary) {
    $b = New-Object System.Windows.Forms.Button
    $b.Text = $Text
    $b.Location = New-Object System.Drawing.Point($X, $Y)
    $b.Size = New-Object System.Drawing.Size($W, $H)
    $b.FlatStyle = 'Flat'; $b.Cursor = 'Hand'
    if ($Primary) {
        $b.BackColor = $Theme.Accent; $b.ForeColor = $Theme.White; $b.Font = $FontBold
        $b.FlatAppearance.BorderSize = 0
        $b.FlatAppearance.MouseOverBackColor = $Theme.AccentHov
    }
    else {
        $b.BackColor = $Theme.White; $b.ForeColor = $Theme.Text
        $b.FlatAppearance.BorderColor = $Theme.Border
        $b.FlatAppearance.MouseOverBackColor = $Theme.Panel
    }
    $Parent.Controls.Add($b); $b
}

function New-Pill($Parent, $X, $Fore, $Back) {
    $p = New-Object System.Windows.Forms.Label
    $p.AutoSize = $false
    $p.Size = New-Object System.Drawing.Size(170, 30)
    $p.Location = New-Object System.Drawing.Point($X, 12)
    $p.TextAlign = 'MiddleCenter'; $p.Font = $FontCount
    $p.ForeColor = $Fore; $p.BackColor = $Back
    $Parent.Controls.Add($p); $p
}

# --- Fenêtre
$form = New-Object System.Windows.Forms.Form
$form.Text = 'Audit des fichiers - mc-media.com'
$form.Size = New-Object System.Drawing.Size(1280, 780)
$form.MinimumSize = New-Object System.Drawing.Size(1180, 520)
$form.StartPosition = 'CenterScreen'
$form.BackColor = $Theme.White
$form.Font = $FontUi

# --- Bandeau du haut
$header = New-Object System.Windows.Forms.Panel
$header.Dock = 'Top'; $header.Height = 72; $header.BackColor = $Theme.Header
$lblTitle = New-Label $header 'Audit des fichiers' 18 10
$lblTitle.Font = $FontTitle; $lblTitle.ForeColor = $Theme.White
$lblSub = New-Label $header 'Qui a supprimé ou créé quels fichiers et dossiers, et quand' 21 44
$lblSub.ForeColor = $Theme.HeaderSub
$lblBrandTop = New-Object System.Windows.Forms.Label
$lblBrandTop.Text = 'fait par mc-media.com'
$lblBrandTop.Dock = 'Right'; $lblBrandTop.AutoSize = $false; $lblBrandTop.Width = 240
$lblBrandTop.TextAlign = 'MiddleRight'; $lblBrandTop.ForeColor = $Theme.HeaderSub
$lblBrandTop.Padding = New-Object System.Windows.Forms.Padding(0, 0, 22, 0)
$header.Controls.Add($lblBrandTop)

# --- Zone de recherche
$opts = New-Object System.Windows.Forms.Panel
$opts.Dock = 'Top'; $opts.Height = 132; $opts.BackColor = $Theme.Panel
$optsLine = New-Object System.Windows.Forms.Panel
$optsLine.Dock = 'Bottom'; $optsLine.Height = 1; $optsLine.BackColor = $Theme.Border
$opts.Controls.Add($optsLine)

[void](New-Label $opts 'Serveurs (séparés par des virgules)' 20 12 -Muted)
$txtServers = New-TextBox $opts 20 30 280
$txtServers.Text = $env:COMPUTERNAME

[void](New-Label $opts 'Du' 316 12 -Muted)
$dtFrom = New-DatePicker $opts 316 30 (Get-Date).AddDays(-7)
[void](New-Label $opts 'Au' 482 12 -Muted)
$dtTo = New-DatePicker $opts 482 30 (Get-Date).Date.AddDays(1).AddMinutes(-1)

[void](New-Label $opts 'Période rapide' 648 12 -Muted)
$x = 648
foreach ($q in @(@('24 h', 1), @('7 jours', 7), @('30 jours', 30))) {
    $b = New-Button $opts $q[0] $x 30 64 27
    $b.Tag = $q[1]
    $b.Add_Click({
        $dtFrom.Value = (Get-Date).AddDays(-[int]$this.Tag)
        $dtTo.Value   = (Get-Date).Date.AddDays(1).AddMinutes(-1)
        $btnSearch.PerformClick()
    })
    $x += 70
}

$btnSearch = New-Button $opts 'Rechercher' 878 27 130 33 -Primary
$btnExport = New-Button $opts 'Exporter CSV' 1018 27 120 33
$form.AcceptButton = $btnSearch

[void](New-Label $opts 'Filtrer par utilisateur' 20 70 -Muted)
$txtUser = New-TextBox $opts 20 88 280
[void](New-Label $opts 'Filtrer par fichier ou dossier' 316 70 -Muted)
$txtPath = New-TextBox $opts 316 88 316

$chkDel         = New-Check $opts 'Suppressions' 648 76 $true
$chkCreate      = New-Check $opts 'Créations' 648 100 $true
$chkUnconfirmed = New-Check $opts 'Inclure renommages / déplacements' 790 76 $false
$chkNoise       = New-Check $opts 'Masquer fichiers temporaires et comptes système' 790 100 $true

# --- Compteurs
$sum = New-Object System.Windows.Forms.Panel
$sum.Dock = 'Top'; $sum.Height = 54; $sum.BackColor = $Theme.White
$pillDel = New-Pill $sum 20  $Theme.Del  $Theme.DelBg
$pillNew = New-Pill $sum 200 $Theme.New  $Theme.NewBg
$pillAll = New-Pill $sum 380 $Theme.Text $Theme.Panel
$lblHint = New-Object System.Windows.Forms.Label
$lblHint.Text = 'Double-clic sur une ligne : copier le chemin complet'
$lblHint.Dock = 'Right'; $lblHint.AutoSize = $false; $lblHint.Width = 380
$lblHint.TextAlign = 'MiddleRight'; $lblHint.ForeColor = $Theme.Muted
$lblHint.Padding = New-Object System.Windows.Forms.Padding(0, 0, 22, 0)
$sum.Controls.Add($lblHint)

# --- Tableau des résultats
$table = New-Object System.Data.DataTable
[void]$table.Columns.Add('Date', [datetime])
foreach ($col in 'Action', 'Utilisateur', 'Nom', 'Emplacement', 'Serveur', 'Processus', 'Chemin') { [void]$table.Columns.Add($col, [string]) }
$view = New-Object System.Data.DataView($table)
$view.Sort = 'Date DESC'

$gridHost = New-Object System.Windows.Forms.Panel
$gridHost.Dock = 'Fill'; $gridHost.BackColor = $Theme.White
$gridHost.Padding = New-Object System.Windows.Forms.Padding(20, 0, 20, 12)

$grid = New-Object System.Windows.Forms.DataGridView
$grid.Dock = 'Fill'
$grid.ReadOnly = $true
$grid.AllowUserToAddRows = $false
$grid.AllowUserToDeleteRows = $false
$grid.AllowUserToResizeRows = $false
$grid.SelectionMode = 'FullRowSelect'
$grid.MultiSelect = $false
$grid.RowHeadersVisible = $false
$grid.AutoSizeColumnsMode = 'Fill'
$grid.BackgroundColor = $Theme.White
$grid.BorderStyle = 'None'
$grid.CellBorderStyle = 'SingleHorizontal'
$grid.GridColor = $Theme.Border
$grid.EnableHeadersVisualStyles = $false
$grid.ColumnHeadersBorderStyle = 'None'
$grid.ColumnHeadersHeightSizeMode = 'DisableResizing'
$grid.ColumnHeadersHeight = 36
$grid.ColumnHeadersDefaultCellStyle.BackColor = $Theme.Panel
$grid.ColumnHeadersDefaultCellStyle.ForeColor = $Theme.Muted
$grid.ColumnHeadersDefaultCellStyle.SelectionBackColor = $Theme.Panel
$grid.ColumnHeadersDefaultCellStyle.Font = $FontBold
$grid.ColumnHeadersDefaultCellStyle.Padding = New-Object System.Windows.Forms.Padding(8, 0, 0, 0)
$grid.DefaultCellStyle.ForeColor = $Theme.Text
$grid.DefaultCellStyle.SelectionBackColor = $Theme.Select
$grid.DefaultCellStyle.SelectionForeColor = $Theme.Text
$grid.DefaultCellStyle.Padding = New-Object System.Windows.Forms.Padding(8, 0, 0, 0)
$grid.AlternatingRowsDefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(250, 251, 252)
$grid.RowTemplate.Height = 30
$grid.DataSource = $view
$gridHost.Controls.Add($grid)

$grid.Add_DataBindingComplete({
    $grid.Columns['Date'].DefaultCellStyle.Format = 'dd/MM/yyyy  HH:mm:ss'
    $grid.Columns['Date'].FillWeight = 13
    $grid.Columns['Action'].FillWeight = 13
    $grid.Columns['Utilisateur'].FillWeight = 15
    $grid.Columns['Nom'].FillWeight = 22
    $grid.Columns['Nom'].DefaultCellStyle.Font = $FontBold
    $grid.Columns['Emplacement'].FillWeight = 30
    $grid.Columns['Emplacement'].DefaultCellStyle.ForeColor = $Theme.Muted
    $grid.Columns['Serveur'].FillWeight = 9
    $grid.Columns['Processus'].Visible = $false
    $grid.Columns['Chemin'].Visible = $false
})

# Colonne Action : pastille colorée (rouge = suppression, vert = création)
$grid.Add_CellFormatting({
    param($sender, $e)
    if ($grid.Columns[$e.ColumnIndex].Name -eq 'Action' -and $e.Value -isnot [System.DBNull] -and $e.Value) {
        $txt = [string]$e.Value
        $color = if ($txt.StartsWith('Supprim')) { $Theme.Del } else { $Theme.New }
        $e.CellStyle.ForeColor = $color
        $e.CellStyle.SelectionForeColor = $color
        $e.CellStyle.Font = $FontBold
        $e.Value = [string][char]0x25CF + '  ' + $txt
        $e.FormattingApplied = $true
    }
})

# --- Barre d'état
$statusBar = New-Object System.Windows.Forms.StatusStrip
$statusBar.BackColor = $Theme.Panel
$statusBar.SizingGrip = $false
$status = New-Object System.Windows.Forms.ToolStripStatusLabel
$status.Spring = $true
$status.TextAlign = 'MiddleLeft'
$status.ForeColor = $Theme.Muted
$status.Text = 'Choisissez la période puis cliquez sur Rechercher.'
$brand = New-Object System.Windows.Forms.ToolStripStatusLabel
$brand.Text = 'Fait par mc-media.com'
$brand.IsLink = $true
$brand.LinkBehavior = 'HoverUnderline'
$brand.LinkColor = $Theme.Accent
$brand.ActiveLinkColor = $Theme.AccentHov
$brand.Add_Click({ try { Start-Process 'https://www.mc-media.com' } catch { } })
[void]$statusBar.Items.Add($status)
[void]$statusBar.Items.Add($brand)

# Ordre d'ajout : la zone "Fill" d'abord, puis les bandeaux (le dernier ajouté se place tout en haut)
$form.Controls.Add($gridHost)
$form.Controls.Add($sum)
$form.Controls.Add($opts)
$form.Controls.Add($header)
$form.Controls.Add($statusBar)

# ---------------------------------------------------------------- Logique de l'interface

function Format-Like([string]$s) {
    ([regex]::Replace($s, '[\[\]\*%]', '[$0]')).Replace("'", "''")
}

function Update-Counters {
    $nDel = 0; $nNew = 0
    foreach ($row in $view) {
        if (([string]$row['Action']).StartsWith('Supprim')) { $nDel++ } else { $nNew++ }
    }
    $pillDel.Text = "$nDel suppression(s)"
    $pillNew.Text = "$nNew création(s)"
    $pillAll.Text = '{0} affiché(s) sur {1}' -f $view.Count, $table.Rows.Count
}

function Update-Filter {
    $parts = @()
    if ($txtUser.Text.Trim()) { $parts += "Utilisateur LIKE '%$(Format-Like $txtUser.Text.Trim())%'" }
    if ($txtPath.Text.Trim()) { $parts += "Chemin LIKE '%$(Format-Like $txtPath.Text.Trim())%'" }
    $view.RowFilter = $parts -join ' AND '
    Update-Counters
}
$txtUser.Add_TextChanged({ Update-Filter })
$txtPath.Add_TextChanged({ Update-Filter })
Update-Counters

$btnSearch.Add_Click({
    # Pendant une recherche, le bouton sert à l'arrêter
    if ($script:Searching) { $script:Cancel = $true; $btnSearch.Enabled = $false; return }

    if ($dtFrom.Value -ge $dtTo.Value) {
        [void][System.Windows.Forms.MessageBox]::Show('La date de début doit être antérieure à la date de fin.', 'Période', 'OK', 'Warning')
        return
    }
    if (-not $chkDel.Checked -and -not $chkCreate.Checked) {
        [void][System.Windows.Forms.MessageBox]::Show('Cochez au moins "Suppressions" ou "Créations".', 'Afficher', 'OK', 'Warning')
        return
    }
    $form.Cursor = 'WaitCursor'
    $script:Searching = $true
    $script:Cancel = $false
    $btnSearch.Text = 'Arrêter'
    $btnSearch.BackColor = $Theme.Del
    $table.Clear()
    Update-Counters
    $errors = @()
    $script:FsErrors = 0
    $servers = $txtServers.Text -split '[,; ]+' | Where-Object { $_ }

    foreach ($s in $servers) {
        if ($script:Cancel) { break }
        try {
            Update-Progress "Lecture du journal de $s ..."
            $rows = @(Get-FileEvents -Server $s -From $dtFrom.Value -To $dtTo.Value `
                        -WantDeletions $chkDel.Checked -WantCreations $chkCreate.Checked `
                        -IncludeUnconfirmed $chkUnconfirmed.Checked -HideNoise $chkNoise.Checked)
            $table.BeginLoadData()
            foreach ($r in $rows) {
                [void]$table.Rows.Add($r.Date, $r.Action, $r.Utilisateur, $r.Nom, $r.Emplacement, $r.Serveur, $r.Processus, $r.Chemin)
            }
            $table.EndLoadData()
        }
        catch { $errors += "$s : $($_.Exception.Message)" }
    }

    Update-Filter
    $status.Text = 'Recherche terminée : du {0:dd/MM/yyyy HH:mm} au {1:dd/MM/yyyy HH:mm} sur {2}' -f $dtFrom.Value, $dtTo.Value, ($servers -join ', ')
    if ($script:FsErrors -gt 0) {
        $status.Text += "   |   Attention : $($script:FsErrors) dossier(s) illisible(s) pendant la vérification des créations (droits, ou partage admin D$ inaccessible)."
    }
    if ($script:Cancel) { $status.Text += '   |   Recherche arrêtée : résultats partiels.' }
    $script:Searching = $false
    $btnSearch.Text = 'Rechercher'
    $btnSearch.BackColor = $Theme.Accent
    $btnSearch.Enabled = $true
    $form.Cursor = 'Default'

    if ($errors) {
        [void][System.Windows.Forms.MessageBox]::Show(
            "Certains serveurs n'ont pas pu être lus :`n`n" + ($errors -join "`n`n") +
            "`n`nVérifiez : droits admin (ou groupe 'Lecteurs des journaux d'événements'), " +
            "règle de pare-feu 'Gestion à distance des journaux d'événements'.",
            'Erreur', 'OK', 'Error')
    }
    elseif ($table.Rows.Count -eq 0 -and -not $script:Cancel) {
        $status.Text = "Rien trouvé sur cette période. Si c'est inattendu, vérifiez que l'audit est actif et que le journal remonte assez loin."
    }
})

$grid.Add_CellDoubleClick({
    param($sender, $e)
    if ($e.RowIndex -ge 0) {
        $p = [string]$grid.Rows[$e.RowIndex].Cells['Chemin'].Value
        [System.Windows.Forms.Clipboard]::SetText($p)
        $status.Text = "Chemin copié : $p"
    }
})

$btnExport.Add_Click({
    if ($view.Count -eq 0) { $status.Text = 'Rien à exporter.'; return }
    $dlg = New-Object System.Windows.Forms.SaveFileDialog
    $dlg.Filter = 'CSV (*.csv)|*.csv'
    $dlg.FileName = 'audit_fichiers_{0:yyyyMMdd_HHmm}.csv' -f (Get-Date)
    if ($dlg.ShowDialog() -eq 'OK') {
        $view | ForEach-Object {
            [pscustomobject]@{
                Date        = $_['Date'].ToString('dd/MM/yyyy HH:mm:ss')
                Action      = $_['Action']
                Utilisateur = $_['Utilisateur']
                Chemin      = $_['Chemin']
                Serveur     = $_['Serveur']
                Processus   = $_['Processus']
            }
        } | Export-Csv -Path $dlg.FileName -Delimiter ';' -Encoding UTF8 -NoTypeInformation
        $status.Text = "Exporté : $($dlg.FileName)"
    }
})

[void]$form.ShowDialog()
