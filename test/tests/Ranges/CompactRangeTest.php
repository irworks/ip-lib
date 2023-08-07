<?php

namespace IPLib\Test\Ranges;

use IPLib\Factory;
use IPLib\ParseStringFlag;
use IPLib\Test\TestCase;

/**
 * @see http://publibn.boulder.ibm.com/doc_link/en_US/a_doc_lib/libs/commtrf2/inet_addr.htm
 */
class CompactRangeTest extends TestCase
{
    public function provideTestCases()
    {
        return array(
            array('1.2.3.4-1.2.3.5', '1.2.3.4', '1.2.3.5'),
            array('1.2.3.4-1.2.3.15', '1.2.3.4', '1.2.3.15'),
            array('1.2.1.0-1.2.3.5', '1.2.1.0', '1.2.3.5'),
            array('0.0.0.0-255.255.255.255', '0.0.0.0', '255.255.255.255'),
        );
    }

    /**
     * @dataProvider provideTestCases
     *
     * @param string $inputString

     * @param string $expectedStartAddressString
     * @param string $expectedEndAddressString
     */
    public function testBoundaries($inputString, $expectedStartAddressString, $expectedEndAddressString)
    {
        $range = Factory::parseRangeString($inputString, ParseStringFlag::IPV4SUBNET_MAYBE_COMPACT);
        $this->assertInstanceOf('IPLib\Range\Range', $range);

        $this->assertSame((string) $range->getStartAddress(), $expectedStartAddressString, 'Start address');
        $this->assertSame((string) $range->getEndAddress(), $expectedEndAddressString, 'End address');
    }
}
