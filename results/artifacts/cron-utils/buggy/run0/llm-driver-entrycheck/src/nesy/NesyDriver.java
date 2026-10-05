package nesy;

import com.cronutils.parser.CronParser;
import com.cronutils.parser.FieldParser;
import com.cronutils.parser.CronParserField;
import com.cronutils.descriptor.CronDescriptor;
import com.cronutils.validation.CronValidator;
import com.cronutils.model.definition.CronDefinition;
import com.cronutils.model.field.CronFieldName;
import com.cronutils.model.field.constraint.FieldConstraints;
import com.cronutils.model.field.expression.FieldExpression;
import com.cronutils.model.Cron;
import com.cronutils.model.field.CronField;

import java.util.HashMap;
import java.util.Map;
import java.util.ResourceBundle;
import javax.validation.ConstraintValidatorContext;

public class NesyDriver {
    public static void main(String[] args) {
        try {
            // Entry point 1: CronParser.parse()
            CronDefinition cronDefinition = null; // Benign constant, not attacker-controlled
            CronParser parser = new CronParser(cronDefinition);
            String taintedCronString = nesy.Taint.src();
            parser.parse(taintedCronString);
        } catch (Throwable t) {}

        try {
            // Entry point 2: FieldParser.parse()
            FieldConstraints constraints = null; // Benign constant
            FieldParser fieldParser = new FieldParser(constraints);
            String taintedFieldString = nesy.Taint.src();
            fieldParser.parse(taintedFieldString);
        } catch (Throwable t) {}

        try {
            // Entry point 3: CronParserField.parse()
            CronFieldName fieldName = CronFieldName.MINUTE; // Benign constant
            FieldConstraints constraints = null; // Benign constant
            CronParserField cronParserField = new CronParserField(fieldName, constraints);
            String taintedFieldString = nesy.Taint.src();
            cronParserField.parse(taintedFieldString);
        } catch (Throwable t) {}

        try {
            // Entry point 4: CronDescriptor.describeDayOfWeek()
            // CronDescriptor constructor is private in newer versions of cron-utils.
            // We cannot instantiate it directly. Removing this entry point as it cannot be made to compile.
        } catch (Throwable t) {}

        try {
            // Entry point 5: CronDescriptor.describeDayOfMonth()
            // CronDescriptor constructor is private in newer versions of cron-utils.
            // We cannot instantiate it directly. Removing this entry point as it cannot be made to compile.
        } catch (Throwable t) {}

        try {
            // Entry point 6: CronDescriptor.describeHHmmss()
            // CronDescriptor constructor is private in newer versions of cron-utils.
            // We cannot instantiate it directly. Removing this entry point as it cannot be made to compile.
        } catch (Throwable t) {}

        try {
            // Entry point 7: CronDescriptor.describeMonth()
            // CronDescriptor constructor is private in newer versions of cron-utils.
            // We cannot instantiate it directly. Removing this entry point as it cannot be made to compile.
        } catch (Throwable t) {}

        try {
            // Entry point 8: CronDescriptor.describeYear()
            // CronDescriptor constructor is private in newer versions of cron-utils.
            // We cannot instantiate it directly. Removing this entry point as it cannot be made to compile.
        } catch (Throwable t) {}

        try {
            // Entry point 9: CronValidator.isValid()
            CronValidator validator = new CronValidator();
            String taintedCronString = nesy.Taint.src();
            ConstraintValidatorContext context = null; // Benign constant
            validator.isValid(taintedCronString, context);
        } catch (Throwable t) {}
    }
}