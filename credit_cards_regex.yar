rule credit_cards_regex : credit_cards stage_indev
{
    meta:
        title = "credit cards"
        description = "credit card events"
        stage = "in-dev"
        date = "01/01/2018"
        modified = "18/7/2021"
        author = "UKN"
        references = "all credit cards"
        falsepositives = "possible"
    strings:
        $hex00 = { 50 4B 03 04 } // apk hex 
        $hex01 = { 75 73 74 61 72 } // tar hex 
        $hex02 = { 37 7A BC AF 27 1C } // 7zip hex 
        $hex03 = { 42 5A 68 } // BZ2 hex 
        $hex04 = { 1F 8B  } // GZ hex
        $hex05 = { FD 37 7A 58 5A }  // XZ hex
        $hex06 = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF } // MZ Hex
        $CARD = /(\d{4})-?(\d{4})-?(\d{4})-?(\d{4})/ // CARD
    condition:
        $CARD and not $hex00 at 0 and not $hex01 at 0 and not $hex02 at 0 and not $hex03 at 0 and not $hex04 at 0 and not $hex05 at 0 and not $hex06 at 0 and filesize > 1KB
}
