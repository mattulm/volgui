rule mwi_document : exploitdoc
{
    meta:
        description = "MWI generated document"
 
    strings:
        $field_creation_tag = "{\\field{\\*\\fldinst { INCLUDEPICTURE"
        $mwistat_url = ".php?id="
        $field_closing_tag = "\\\\* MERGEFORMAT \\\\d}}{\\fldrslt}}"
 
    condition:
        all of them
}