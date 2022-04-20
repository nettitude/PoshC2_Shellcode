SECTIONS
{
    .configuration : {
        PROVIDE(posh_config_start = .);
        *(.configuration)
        PROVIDE(posh_config_end = .);
    }
}
INSERT AFTER .bss;
