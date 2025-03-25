def build_entity_packet(char, category="Player"):
    name, class_name, level, _, _, _, _, _, hair_color, skin_color, shirt_color, pant_color, gear = char
    return f"""
<Entity Category='{category}' Name='{name}' Class='{class_name}' Level='{level}'
HairColor='{hair_color}' SkinColor='{skin_color}' ShirtColor='{shirt_color}' PantsColor='{pant_color}'>
{gear}
</Entity>"""