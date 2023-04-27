package com.miportfolio.aar.Dto;

import jakarta.validation.constraints.NotBlank;

public class dtohys {
    @NotBlank
    private String nombre;
    @NotBlank
    private int porcentaje;

    public String getNombre() {
        return nombre;
    }

    public void setNombre(String nombre) {
        this.nombre = nombre;
    }

    public int getPorcentaje() {
        return porcentaje;
    }

    public void setPorcentaje(int porcentaje) {
        this.porcentaje = porcentaje;
    }
    
    
}
