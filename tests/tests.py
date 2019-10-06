import unittest
import json
import mrextractor


PE_EXE_DIR = "./test_assets/executables/pe"
ELF_EXE_DIR = "test_assets/executables/elf"

EXPECTED_FEATURES_DIR = "test_assets/expected_features"
EXTRACTED_FEATURES_DIR = "test_assets/extracted_features"
CONFS_DIR = "test_assets/extractor_confs"

PE_0_HASH = "071df5b74f08fb5a4ce13a6cd2e7f485"
ELF_0_HASH = "0e1631f5eaadf5ac5010530077727092"


class TestExtractor(unittest.TestCase):

    def test_creation(self):
        """
        Test the extractor creation using a test conf file.
        """
        conf_file = "test_assets/extractor_conf.yaml"
        out_folder = "test_assets/extracted_features"
        extractor = mrextractor.new(conf_file, PE_EXE_DIR, out_folder)
        feature_list = list(extractor.features.keys())
        expected_feature_list = sorted([
            'base.ByteCounts',
            'base.BinaryImage',
            'base.FileSize',
            'base.URLs',
            'base.ImportedFunctions',
            'base.ExportedFunctions',
            'base.Strings',
            'pe.PEGeneralFileInfo',
            'pe.PEMSDOSHeader',
            'pe.PEHeader',
            'pe.PEOptionalHeader',
            'pe.PELibraries',
            'pe.PESections',
            'elf.ELFHeader',
            'elf.ELFLibraries',
            'elf.ELFSections',
        ])
        self.assertEqual(
            sorted(feature_list),
            expected_feature_list,
            "Imported features don't match"
        )

    def test_PE_Header(self):
        """
        Test the extracted features of Pe Header !
        """

        feature_name = "pe_header"

        conf_file = "{}/{}_conf.yaml".format(CONFS_DIR, feature_name)
        out_folder = "{}/{}".format(EXTRACTED_FEATURES_DIR, feature_name)
        expected = "{}/{}.json".format(EXPECTED_FEATURES_DIR,
                                       feature_name)
        extracted = "{}/json/0/{}.json".format(out_folder, PE_0_HASH)

        extractor = mrextractor.new(conf_file, PE_EXE_DIR, out_folder)
        extractor.extract_batch()

        with open(expected, "rb") as f1:
            expected_feature_dict = json.load(f1)
        with open(extracted, "rb") as f2:
            extracted_feature_dict = json.load(f2)

        self.assertEqual(
            extracted_feature_dict,
            expected_feature_dict,
            "The extracted features of Pe Header don't match"
        )

    def test_Libraries(self):
        """
        Test the extracted features of Libraries !
        """

        feature_name = "libraries"

        conf_file = "{}/{}_conf.yaml".format(CONFS_DIR, feature_name)
        out_folder = "{}/{}".format(EXTRACTED_FEATURES_DIR, feature_name)
        expected = "{}/{}.json".format(EXPECTED_FEATURES_DIR,
                                       feature_name)
        extracted = "{}/json/0/{}.json".format(out_folder, PE_0_HASH)

        extractor = mrextractor.new(conf_file, PE_EXE_DIR, out_folder)
        extractor.extract_batch()

        with open(expected, "rb") as f1:
            expected_feature_dict = json.load(f1)
        with open(extracted, "rb") as f2:
            extracted_feature_dict = json.load(f2)

        self.assertEqual(
            extracted_feature_dict,
            expected_feature_dict,
            "The extracted features of Libraries don't match"
        )

    def test_Sections(self):
        """
        Test the extracted features of Sections !
        """

        feature_name = "sections"

        conf_file = "{}/{}_conf.yaml".format(CONFS_DIR, feature_name)
        out_folder = "{}/{}".format(EXTRACTED_FEATURES_DIR, feature_name)
        expected = "{}/{}.json".format(EXPECTED_FEATURES_DIR,
                                       feature_name)
        extracted = "{}/json/0/{}.json".format(out_folder, PE_0_HASH)

        extractor = mrextractor.new(conf_file, PE_EXE_DIR, out_folder)
        extractor.extract_batch()
        # feature_dict = extractor.features

        with open(expected, "rb") as f1:
            expected_feature_dict = json.load(f1)
        with open(extracted, "rb") as f2:
            extracted_feature_dict = json.load(f2)

        self.assertEqual(
            extracted_feature_dict,
            expected_feature_dict,
            "The extracted features of Sections don't match"
        )

    def test_general_file_info(self):
        """
        Testing the file general informations extraction .
        """

        feature_name = "general_file_info"

        conf_file = "{}/{}_conf.yaml".format(CONFS_DIR, feature_name)
        out_folder = "{}/{}".format(EXTRACTED_FEATURES_DIR, feature_name)
        expected = "{}/{}.json".format(EXPECTED_FEATURES_DIR,
                                       feature_name)
        extracted = "{}/json/0/{}.json".format(out_folder, PE_0_HASH)

        extractor = mrextractor.new(conf_file, PE_EXE_DIR, out_folder)
        extractor.extract_batch()

        with open(expected, "rb") as f1:
            expected_feature_dict = json.load(f1)
        with open(extracted, "rb") as f2:
            extracted_feature_dict = json.load(f2)

        self.assertEqual(
            extracted_feature_dict,
            expected_feature_dict,
            "extracted general file informations don't match"
        )

    def test_msdos_header(self):
        """
        Testing the Msdos Header extraction .
        """

        feature_name = "msdos_header"

        conf_file = "{}/{}_conf.yaml".format(CONFS_DIR, feature_name)
        out_folder = "{}/{}".format(EXTRACTED_FEATURES_DIR, feature_name)
        expected = "{}/{}.json".format(EXPECTED_FEATURES_DIR,
                                       feature_name)
        extracted = "{}/json/0/{}.json".format(out_folder, PE_0_HASH)

        extractor = mrextractor.new(conf_file, PE_EXE_DIR, out_folder)
        extractor.extract_batch()

        with open(expected, "rb") as f1:
            expected_feature_dict = json.load(f1)
        with open(extracted, "rb") as f2:
            extracted_feature_dict = json.load(f2)

        self.assertEqual(
            extracted_feature_dict,
            expected_feature_dict,
            "msdos header dosen't match"
        )

    def test_optional_header(self):
        """
        Testing the optional header extraction using a test conf file.
        """

        feature_name = "optional_header"

        conf_file = "{}/{}_conf.yaml".format(CONFS_DIR, feature_name)
        out_folder = "{}/{}".format(EXTRACTED_FEATURES_DIR, feature_name)
        expected = "{}/{}.json".format(EXPECTED_FEATURES_DIR,
                                       feature_name)
        extracted = "{}/json/0/{}.json".format(out_folder, PE_0_HASH)

        extractor = mrextractor.new(conf_file, PE_EXE_DIR, out_folder)
        extractor.extract_batch()

        with open(expected, "rb") as f1:
            expected_feature_dict = json.load(f1)
        with open(extracted, "rb") as f2:
            extracted_feature_dict = json.load(f2)

        self.assertEqual(
            extracted_feature_dict,
            expected_feature_dict,
            "Optional Header dosen't match"
        )

    def test_file_size(self):
        """
        Testing file size extarction using a test conf file.
        """

        feature_name = "file_size"

        conf_file = "{}/{}_conf.yaml".format(CONFS_DIR, feature_name)
        out_folder = "{}/{}".format(EXTRACTED_FEATURES_DIR, feature_name)
        expected = "{}/{}.json".format(EXPECTED_FEATURES_DIR,
                                       feature_name)
        extracted = "{}/json/0/{}.json".format(out_folder, PE_0_HASH)

        extractor = mrextractor.new(conf_file, PE_EXE_DIR, out_folder)
        extractor.extract_batch()

        with open(expected, "rb") as f1:
            expected_feature_dict = json.load(f1)
        with open(extracted, "rb") as f2:
            extracted_feature_dict = json.load(f2)

        self.assertEqual(
            extracted_feature_dict,
            expected_feature_dict,
            "file size dosen't match"
        )

    def test_urls(self):
        """
        Testing URLs extarction using a test conf file.
        """

        feature_name = "urls"

        conf_file = "{}/{}_conf.yaml".format(CONFS_DIR, feature_name)
        out_folder = "{}/{}".format(EXTRACTED_FEATURES_DIR, feature_name)
        expected = "{}/{}.json".format(EXPECTED_FEATURES_DIR,
                                       feature_name)
        extracted = "{}/json/0/{}.json".format(out_folder, PE_0_HASH)

        extractor = mrextractor.new(conf_file, PE_EXE_DIR, out_folder)
        extractor.extract_batch()

        with open(expected, "rb") as f1:
            expected_feature_dict = json.load(f1)
        with open(extracted, "rb") as f2:
            extracted_feature_dict = json.load(f2)

        self.assertEqual(
            extracted_feature_dict,
            expected_feature_dict,
            "urls don't match"
        )

    def test_imported_functions(self):
        """
        Testing imported functions extarction using a test conf file.
        """

        feature_name = "imported_functions"

        conf_file = "{}/{}_conf.yaml".format(CONFS_DIR, feature_name)
        out_folder = "{}/{}".format(EXTRACTED_FEATURES_DIR, feature_name)
        expected = "{}/{}.json".format(EXPECTED_FEATURES_DIR,
                                       feature_name)
        extracted = "{}/json/0/{}.json".format(out_folder, PE_0_HASH)

        extractor = mrextractor.new(conf_file, PE_EXE_DIR, out_folder)
        extractor.extract_batch()

        with open(expected, "rb") as f1:
            expected_feature_dict = json.load(f1)
        with open(extracted, "rb") as f2:
            extracted_feature_dict = json.load(f2)

        self.assertEqual(
            extracted_feature_dict,
            expected_feature_dict,
            "imported functions don't match"
        )

    def test_byte_counts(self):
        """
        Testing the byte counts extraction using a test conf file.
        """

        feature_name = "byte_counts"

        conf_file = "{}/{}_conf.yaml".format(CONFS_DIR, feature_name)
        out_folder = "{}/{}".format(EXTRACTED_FEATURES_DIR, feature_name)
        expected = "{}/{}.json".format(EXPECTED_FEATURES_DIR,
                                       feature_name)
        extracted = "{}/json/0/{}.json".format(out_folder, PE_0_HASH)

        extractor = mrextractor.new(conf_file, PE_EXE_DIR, out_folder)
        extractor.extract_batch()

        with open(expected, "rb") as f1:
            expected_feature_dict = json.load(f1)
        with open(extracted, "rb") as f2:
            extracted_feature_dict = json.load(f2)

        self.assertEqual(
            extracted_feature_dict,
            expected_feature_dict,
            "Byte Counts dosen't match"
        )

    def test_exported_functions(self):
        """
        Testing exported functions extarction using a test conf file.
        """

        feature_name = "exported_functions"

        conf_file = "{}/{}_conf.yaml".format(CONFS_DIR, feature_name)
        out_folder = "{}/{}".format(EXTRACTED_FEATURES_DIR, feature_name)
        expected = "{}/{}.json".format(EXPECTED_FEATURES_DIR,
                                       feature_name)
        extracted = "{}/json/0/{}.json".format(out_folder, PE_0_HASH)

        extractor = mrextractor.new(conf_file, PE_EXE_DIR, out_folder)
        extractor.extract_batch()

        with open(expected, "rb") as f1:
            expected_feature_dict = json.load(f1)
        with open(extracted, "rb") as f2:
            extracted_feature_dict = json.load(f2)

        self.assertEqual(
            extracted_feature_dict,
            expected_feature_dict,
            "exported functions don't match"
        )

    def test_binary_image(self):
        """
        Testing the binary image extraction using a test conf file.
        """

        from PIL import Image, ImageChops

        """
        # Funtion that compares the differences of the two images .
        @param1 image, @param2 image   (extracted & expected images)

        @return an image (difference between pixels)
        if they are equal then it returns a black image
        """
        def assertImage(pic_1,  pic_2):
            diff = ImageChops.difference(pic_1, pic_2)
            theDifferenceImage = diff.convert('RGB')
            theDifferenceImage.paste(pic_2, mask=diff)
            return theDifferenceImage

        # conf_file = "test_assets/extractor_confs/binary_image_conf.yaml"
        # out_folder = "test_assets/extracted_features/binary_image"
        # extractor = mrextractor.new(conf_file, PE_EXE_DIR, out_folder)
        # extractor.extract_batch()

        # extracted_image = Image.open(
        #     "test_assets/expected_features_images/binary_image.png")
        # expected_image = Image.open(
        #     out_folder + "/image/binary_image/0/071df5b74f08fb5a4ce13a6cd2e7f485.png")
        # difference = assertImage(extracted_image, expected_image)

        feature_name = "binary_image"

        conf_file = "{}/{}_conf.yaml".format(CONFS_DIR, feature_name)
        out_folder = "{}/{}".format(EXTRACTED_FEATURES_DIR, feature_name)
        expected = "{}/{}.png".format(EXPECTED_FEATURES_DIR,
                                      feature_name)
        extracted = "{}/image/binary_image/0/{}.png".format(
            out_folder, PE_0_HASH)

        extractor = mrextractor.new(conf_file, PE_EXE_DIR, out_folder)
        extractor.extract_batch()
        extracted_image = Image.open(expected)
        expected_image = Image.open(extracted)
        difference = assertImage(extracted_image, expected_image)

        # getbbox(): verifying if all pixels are black
        # it return 'None' if they are
        # if not then the pixels where they are changed
        self.assertTrue(not difference.getbbox(), "Binary images don't match")

    def test_strings(self):
        """
        Testing exported functions extarction using a test conf file.
        """

        feature_name = "strings"

        conf_file = "{}/{}_conf.yaml".format(CONFS_DIR, feature_name)
        out_folder = "{}/{}".format(EXTRACTED_FEATURES_DIR, feature_name)
        expected = "{}/{}.json".format(EXPECTED_FEATURES_DIR,
                                       feature_name)
        extracted = "{}/json/0/{}.json".format(out_folder, PE_0_HASH)

        extractor = mrextractor.new(conf_file, PE_EXE_DIR, out_folder)
        extractor.extract_batch()

        with open(expected, "rb") as f1:
            expected_feature_dict = json.load(f1)
        with open(extracted, "rb") as f2:
            extracted_feature_dict = json.load(f2)

        self.assertEqual(
            extracted_feature_dict,
            expected_feature_dict,
            "strings don't match"
        )

    def test_elf_header(self):
        """
        Testing the extraction of informations from the header of an example
        ELF file.
        """

        feature_name = "elf_header"

        conf_file = "{}/{}_conf.yaml".format(CONFS_DIR, feature_name)
        out_folder = "{}/{}".format(EXTRACTED_FEATURES_DIR, feature_name)
        expected = "{}/{}.json".format(EXPECTED_FEATURES_DIR,
                                       feature_name)
        extracted = "{}/json/0/{}.json".format(out_folder, ELF_0_HASH)

        extractor = mrextractor.new(conf_file, ELF_EXE_DIR, out_folder)
        extractor.extract_batch()

        with open(expected, "rb") as f1:
            expected_feature_dict = json.load(f1)
        with open(extracted, "rb") as f2:
            extracted_feature_dict = json.load(f2)

        self.assertEqual(
            extracted_feature_dict,
            expected_feature_dict,
            "ELF header don't match the expected output"
        )

    def test_elf_sections(self):
        """
        Testing the extraction of informations from the sections of an example
        ELF file.
        """

        feature_name = "elf_sections"

        conf_file = "{}/{}_conf.yaml".format(CONFS_DIR, feature_name)
        out_folder = "{}/{}".format(EXTRACTED_FEATURES_DIR, feature_name)
        expected = "{}/{}.json".format(EXPECTED_FEATURES_DIR,
                                       feature_name)
        extracted = "{}/json/0/{}.json".format(out_folder, ELF_0_HASH)

        extractor = mrextractor.new(conf_file, ELF_EXE_DIR, out_folder)
        extractor.extract_batch()

        with open(expected, "rb") as f1:
            expected_feature_dict = json.load(f1)
        with open(extracted, "rb") as f2:
            extracted_feature_dict = json.load(f2)

        self.assertEqual(
            extracted_feature_dict,
            expected_feature_dict,
            "ELF Sections don't match the expected output"
        )

    def test_elf_libraries(self):
        """
        Testing the extraction of ELF library names
        """

        feature_name = "elf_libraries"

        conf_file = "{}/{}_conf.yaml".format(CONFS_DIR, feature_name)
        out_folder = "{}/{}".format(EXTRACTED_FEATURES_DIR, feature_name)
        expected = "{}/{}.json".format(EXPECTED_FEATURES_DIR,
                                       feature_name)
        extracted = "{}/json/0/{}.json".format(out_folder, ELF_0_HASH)

        extractor = mrextractor.new(conf_file, ELF_EXE_DIR, out_folder)
        extractor.extract_batch()

        with open(expected, "rb") as f1:
            expected_feature_dict = json.load(f1)
        with open(extracted, "rb") as f2:
            extracted_feature_dict = json.load(f2)

        self.assertEqual(
            extracted_feature_dict,
            expected_feature_dict,
            "ELF Sections don't match the expected output"
        )


if __name__ == '__main__':
    unittest.main()
