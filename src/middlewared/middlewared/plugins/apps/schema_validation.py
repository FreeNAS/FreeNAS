from middlewared.schema import Dict
from middlewared.service import Service

from .schema_utils import construct_schema, get_list_item_from_value, NOT_PROVIDED, RESERVED_NAMES


VALIDATION_REF_MAPPING = {  # FIXME: See which are no longer valid
    'definitions/certificate': 'certificate',
    'definitions/certificateAuthority': 'certificate_authority',
    'validations/containerImage': 'container_image',
    'validations/nodePort': 'port_available_on_node',
    'validations/hostPath': 'custom_host_path',
    'normalize/ixVolume': 'ix_mount_path',
    'normalize/acl': 'acl_entries',
    'validations/lockedHostPath': 'locked_host_path',
    'validations/hostPathAttachments': 'host_path_attachments',
}


class AppSchemaService(Service):

    class Config:
        namespace = 'app.schema'
        private = True

    async def validate_values(self, app_version_details, new_values, update, release_data=None):
        for k in RESERVED_NAMES:
            new_values.pop(k[0], None)

        verrors, new_values, dict_obj, schema_name = (
            construct_schema(
                app_version_details, new_values, update, (release_data or {}).get('config', NOT_PROVIDED)
            )
        ).values()

        verrors.check()

        # If schema is okay, we see if we have question specific validation to be performed
        questions = {}
        for variable in app_version_details['schema']['questions']:
            questions[variable['variable']] = variable
        for key in filter(lambda k: k in questions, new_values):
            await self.validate_question(
                verrors=verrors,
                parent_value=new_values,
                value=new_values[key],
                question=questions[key],
                parent_attr=dict_obj,
                var_attr=dict_obj.attrs[key],
                schema_name=f'{schema_name}.{questions[key]["variable"]}',
                release_data=release_data,
            )

        verrors.check()

        return dict_obj

    async def validate_question(
        self, verrors, parent_value, value, question, parent_attr, var_attr, schema_name, release_data=None
    ):
        schema = question['schema']

        if schema['type'] == 'dict' and value:
            dict_attrs = {v['variable']: v for v in schema['attrs']}
            for k in filter(lambda k: k in dict_attrs, value):
                await self.validate_question(
                    verrors, value, value[k], dict_attrs[k],
                    var_attr, var_attr.attrs[k], f'{schema_name}.{k}', release_data,
                )

        elif schema['type'] == 'list' and value:
            for index, item in enumerate(value):
                item_index, attr = get_list_item_from_value(item, var_attr)
                if attr:
                    await self.validate_question(
                        verrors, value, item, schema['items'][item_index],
                        var_attr, attr, f'{schema_name}.{index}', release_data,
                    )

        # FIXME: See if this is valid or not and port appropriately
        '''
        if schema['type'] == 'hostpath':
            await self.validate_host_path_field(value, verrors, schema_name)
        '''
        for validator_def in filter(lambda k: k in VALIDATION_REF_MAPPING, schema.get('$ref', [])):
            await self.middleware.call(
                f'app.schema.validate_{VALIDATION_REF_MAPPING[validator_def]}',
                verrors, value, question, schema_name, release_data,
            )

        subquestions_enabled = (
            schema['show_subquestions_if'] == value
            if 'show_subquestions_if' in schema else 'subquestions' in schema
        )
        if subquestions_enabled:
            for sub_question in schema.get('subquestions', []):
                # TODO: Add support for nested subquestions validation for List schema types.
                if isinstance(parent_attr, Dict) and sub_question['variable'] in parent_value:
                    item_key, attr = sub_question['variable'], parent_attr.attrs[sub_question['variable']]
                    await self.validate_question(
                        verrors, parent_value, parent_value[sub_question['variable']], sub_question,
                        parent_attr, attr, f'{schema_name}.{item_key}', release_data,
                    )

        return verrors
