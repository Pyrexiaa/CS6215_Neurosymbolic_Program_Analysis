package nesy;

import java.io.File;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.ResourceBundle;

public class NesyDriver {
    public static void main(String[] args) {
        try {
            com.cronutils.parser.CronParser parser = new com.cronutils.parser.CronParser(com.cronutils.model.definition.CronDefinitionBuilder.instanceForDefinition(com.cronutils.model.definition.CronDefinition.QUARTZ).build());
            parser.parse(nesy.Taint.src());
        } catch (Throwable t) {}

        try {
            com.cronutils.parser.FieldParser fieldParser = new com.cronutils.parser.FieldParser(new com.cronutils.model.field.constraint.FieldConstraints(new java.util.HashMap<>(), new java.util.HashMap<>(), new java.util.HashSet<>(), 0, 0, false));
            fieldParser.parse(nesy.Taint.src());
        } catch (Throwable t) {}

        try {
            com.cronutils.parser.CronParserField cronParserField = new com.cronutils.parser.CronParserField(com.cronutils.model.field.CronFieldName.SECOND, new com.cronutils.model.field.constraint.FieldConstraints(new java.util.HashMap<>(), new java.util.HashMap<>(), new java.util.HashSet<>(), 0, 0, false));
            cronParserField.parse(nesy.Taint.src());
        } catch (Throwable t) {}

        try {
            com.cronutils.validation.CronValidator validator = new com.cronutils.validation.CronValidator(com.cronutils.model.definition.CronDefinitionBuilder.instanceForDefinition(com.cronutils.model.definition.CronDefinition.QUARTZ).build());
            validator.isValid(nesy.Taint.src(), null);
        } catch (Throwable t) {}

        try {
            com.cronutils.model.CronType.valueOf(nesy.Taint.src());
        } catch (Throwable t) {}

        try {
            com.cronutils.model.field.CronFieldName.valueOf(nesy.Taint.src());
        } catch (Throwable t) {}

        try {
            com.cronutils.model.field.value.SpecialChar.valueOf(nesy.Taint.src());
        } catch (Throwable t) {}

        try {
            com.cronutils.utils.WeekendPolicy.valueOf(nesy.Taint.src());
        } catch (Throwable t) {}

        try {
            com.cronutils.converter.CronConverter converter = new com.cronutils.converter.CronConverter(com.cronutils.model.definition.CronDefinitionBuilder.instanceForDefinition(com.cronutils.model.definition.CronDefinition.QUARTZ).build());
            converter.convert();
        } catch (Throwable t) {}

        try {
            com.cronutils.descriptor.CronDescriptor descriptor = new com.cronutils.descriptor.CronDescriptor(ResourceBundle.getBundle("com.cronutils.descriptor.Messages"));
            Map<com.cronutils.model.field.expression.FieldExpression, String> dayOfWeekMap = new HashMap<>();
            Map<com.cronutils.model.field.value.SpecialChar, String> specialCharMap = new HashMap<>();
            descriptor.describeDayOfWeek(dayOfWeekMap, specialCharMap);
        } catch (Throwable t) {}

        try {
            com.cronutils.descriptor.CronDescriptor descriptor = new com.cronutils.descriptor.CronDescriptor(ResourceBundle.getBundle("com.cronutils.descriptor.Messages"));
            Map<com.cronutils.model.field.expression.FieldExpression, String> dayOfMonthMap = new HashMap<>();
            descriptor.describeDayOfMonth(dayOfMonthMap);
        } catch (Throwable t) {}

        try {
            com.cronutils.descriptor.CronDescriptor descriptor = new com.cronutils.descriptor.CronDescriptor(ResourceBundle.getBundle("com.cronutils.descriptor.Messages"));
            Map<com.cronutils.model.field.expression.FieldExpression, String> hhmmssMap = new HashMap<>();
            descriptor.describeHHmmss(hhmmssMap);
        } catch (Throwable t) {}

        try {
            com.cronutils.descriptor.CronDescriptor descriptor = new com.cronutils.descriptor.CronDescriptor(ResourceBundle.getBundle("com.cronutils.descriptor.Messages"));
            Map<com.cronutils.model.field.expression.FieldExpression, String> monthMap = new HashMap<>();
            descriptor.describeMonth(monthMap);
        } catch (Throwable t) {}

        try {
            com.cronutils.descriptor.CronDescriptor descriptor = new com.cronutils.descriptor.CronDescriptor(ResourceBundle.getBundle("com.cronutils.descriptor.Messages"));
            Map<com.cronutils.model.field.expression.FieldExpression, String> yearMap = new HashMap<>();
            descriptor.describeYear(yearMap);
        } catch (Throwable t) {}

        try {
            com.cronutils.model.field.constraint.FieldConstraints constraints = new com.cronutils.model.field.constraint.FieldConstraints(new java.util.HashMap<>(), new java.util.HashMap<>(), new java.util.HashSet<>(), 0, 0, false);
            constraints.getStringMappingValue(nesy.Taint.src());
        } catch (Throwable t) {}

        try {
            com.cronutils.model.field.expression.Weekdays.valueOf(nesy.Taint.src());
        } catch (Throwable t) {}

        try {
            List<com.cronutils.model.field.expression.FieldExpression> expressions = new ArrayList<>();
            com.cronutils.model.field.expression.FieldExpressionFactory.and(expressions);
        } catch (Throwable t) {}

        try {
            com.cronutils.utils.StringUtils.containsAny(nesy.Taint.src(), new char[]{'*'});
        } catch (Throwable t) {}

        try {
            com.cronutils.utils.StringUtils.isEmpty(nesy.Taint.src());
        } catch (Throwable t) {}

        try {
            com.cronutils.utils.StringUtils.isNumeric(nesy.Taint.src());
        } catch (Throwable t) {}

        try {
            com.cronutils.utils.StringUtils.join(new Object[]{nesy.Taint.src()}, ",");
        } catch (Throwable t) {}

        try {
            com.cronutils.utils.DateUtils.workdaysCount(java.time.ZonedDateTime.now(), 1, new ArrayList<>(), com.cronutils.utils.WeekendPolicy.WEEKDAYS);
        } catch (Throwable t) {}

        try {
            com.cronutils.utils.DateUtils.workdaysCount(java.time.ZonedDateTime.now(), java.time.ZonedDateTime.now(), new ArrayList<>(), com.cronutils.utils.WeekendPolicy.WEEKDAYS);
        } catch (Throwable t) {}

        try {
            com.cronutils.utils.Preconditions.checkNotNull(nesy.Taint.src(), "error");
        } catch (Throwable t) {}

        try {
            com.cronutils.utils.Preconditions.checkNotNullNorEmpty(nesy.Taint.src(), "error");
        } catch (Throwable t) {}

        try {
            com.cronutils.utils.Preconditions.checkNotNullNorEmpty(new ArrayList<>(), "error");
        } catch (Throwable t) {}

        try {
            com.cronutils.utils.Preconditions.checkArgument(true, nesy.Taint.src());
        } catch (Throwable t) {}

        try {
            com.cronutils.utils.Preconditions.checkArgument(true, nesy.Taint.src(), new Object[]{nesy.Taint.src()});
        } catch (Throwable t) {}

        try {
            com.cronutils.utils.Preconditions.checkPositive(1, nesy.Taint.src());
        } catch (Throwable t) {}

        try {
            com.cronutils.utils.Preconditions.checkState(true, nesy.Taint.src(), new Object[]{nesy.Taint.src()});
        } catch (Throwable t) {}

        try {
            com.cronutils.utils.Preconditions.checkNotNull(nesy.Taint.src());
        } catch (Throwable t) {}

        try {
            com.cronutils.StringValidations validations = new com.cronutils.StringValidations(new com.cronutils.model.field.constraint.FieldConstraints(new java.util.HashMap<>(), new java.util.HashMap<>(), new java.util.HashSet<>(), 0, 0, false));
            validations.removeValidChars(nesy.Taint.src());
        } catch (Throwable t) {}
    }
}