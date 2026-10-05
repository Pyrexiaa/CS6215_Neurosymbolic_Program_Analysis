package nesy;

public class NesyDriver {
    public static void main(String[] args) {
        try {
            com.cronutils.model.definition.CronDefinition def = com.cronutils.model.definition.CronDefinitionBuilder.instanceDefinitionFor(com.cronutils.model.CronType.QUARTZ);
            com.cronutils.parser.CronParser parser = new com.cronutils.parser.CronParser(def);
            parser.parse(nesy.Taint.src());
        } catch (Throwable t) {}

        try {
            com.cronutils.model.field.constraint.FieldConstraints constraints = new com.cronutils.model.field.constraint.FieldConstraints(new java.util.HashMap<>(), new java.util.HashMap<>(), new java.util.HashSet<>(), 0, 0, false);
            com.cronutils.parser.FieldParser fieldParser = new com.cronutils.parser.FieldParser(constraints);
            fieldParser.parse(nesy.Taint.src());
        } catch (Throwable t) {}

        try {
            com.cronutils.model.field.constraint.FieldConstraints constraints = new com.cronutils.model.field.constraint.FieldConstraints(new java.util.HashMap<>(), new java.util.HashMap<>(), new java.util.HashSet<>(), 0, 0, false);
            com.cronutils.parser.CronParserField parserField = new com.cronutils.parser.CronParserField(com.cronutils.model.field.CronFieldName.MINUTE, constraints);
            parserField.parse(nesy.Taint.src());
        } catch (Throwable t) {}

        try {
            com.cronutils.validation.CronValidator validator = new com.cronutils.validation.CronValidator();
            validator.isValid(nesy.Taint.src(), null);
        } catch (Throwable t) {}

        try {
            com.cronutils.model.CronType.valueOf(nesy.Taint.src());
        } catch (Throwable t) {}

        try {
            com.cronutils.model.field.CronFieldName.valueOf(nesy.Taint.src());
        } catch (Throwable t) {}

        try {
            com.cronutils.model.field.expression.Weekdays.valueOf(nesy.Taint.src());
        } catch (Throwable t) {}

        try {
            com.cronutils.model.field.value.SpecialChar.valueOf(nesy.Taint.src());
        } catch (Throwable t) {}

        try {
            com.cronutils.utils.WeekendPolicy.valueOf(nesy.Taint.src());
        } catch (Throwable t) {}

        try {
            com.cronutils.model.definition.CronDefinition def = com.cronutils.model.definition.CronDefinitionBuilder.instanceDefinitionFor(com.cronutils.model.CronType.QUARTZ);
            com.cronutils.parser.CronParser parser = new com.cronutils.parser.CronParser(def);
            com.cronutils.model.Cron cron = parser.parse(nesy.Taint.src());
            com.cronutils.converter.CronConverter converter = com.cronutils.converter.CronConverter.using(def);
            converter.convert(cron);
        } catch (Throwable t) {}
    }
}